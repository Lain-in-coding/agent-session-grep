//! Owned uninstall composition. A durable fence is not proof that a reader,
//! native process or SQLite handle exited. Final after-exit cleanup stays pending.
use crate::{
    CliError, RetrievalMode, emit_help, emit_result,
    host_config::{self, Host, McpRegistration},
    managed_purge::SetupArtifactBinding as InventoryBinding,
    native_autostart::{
        AutostartReceipt, ConfigurationState, NativeAutostartStore, NativeLocation,
        SupervisorRegistration, platform,
    },
    native_manager::{self, ManagerError},
    package_installation::{self, Installation, Manifest},
    path_command,
    protocol::{CanonicalCode, Outcome, OutputMode, Page, ProtocolError},
    setup_hosts::{self, LocalCapture, PrivateReceiptLocator, capture_local},
    update_state,
};
use agent_session_grep_adapters_sqlite::{
    SCHEMA_VERSION, SqliteControlStore, WriterLease,
    control::{BackupState, CONTROL_SCHEMA_VERSION, InstallationLockAuthority},
    managed_cache::ManagedCache,
    managed_control_lifetime::{
        ControlRetirement, RETIREMENT_MARKER, RETIREMENT_PENDING_MARKER, RetiredControlFile,
        RetirementBinding, RetirementDrainGuards, RetirementIntent,
    },
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
    managed_maintenance::{PurgeOutcome, purge_backup, verify_backup_until},
    managed_purge,
    managed_store::{ManagedStore, validate_catalog_path},
};
use agent_session_grep_ports::{
    PortError,
    control::{
        CanonicalLocator, ControlId, ControlStatus, ControlStore, ExcludedRegion, MaintenanceFence,
        MaintenancePhase, MaintenanceState, PurgeState, ReadPolicy, RequestIntersection, RootKind,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
pub(crate) const HELP: &str = "Remove verified ASG-owned state.\n\
USAGE: asg [--db <catalog>] uninstall [--keep-data] [--install-prefix <prefix>]\n\
Default removes proven owned catalog, continuation cache and registered backups.\n\
--keep-data retains catalog, current policy and pending purges together; cached\n\
continuations are cleared. Unchanged owned host and login/PATH nodes are removed.\n\
Edited or unowned settings remain. Provider histories and shared parents remain.\n\
A durable uninstall fence blocks new evidence and updates while cleanup drains.\n\
Open control handles or missing verified after-exit helpers remain pending cleanup\n\
(exit 10); this command never claims that locked executables were deleted.";
#[path = "managed_uninstall_cleanup.rs"]
mod managed_uninstall_cleanup;
/// Internal entry only; always silent, including malformed or failed handoffs.
pub(crate) fn intercept(args: &[OsString]) -> Option<i32> {
    managed_uninstall_cleanup::intercept(args)
}
pub(crate) const WINDOWS_TAIL_HELPER: &str = managed_uninstall_cleanup::WINDOWS_TAIL_HELPER;
const BUDGET: Duration = Duration::from_secs(30);
const STATE_SCHEMA: &str = "asg.uninstall-state/v1";
const OWNER_SCHEMA: &str = "asg.uninstall-owner/v1";
const INVENTORY_LIMIT: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 1024;
const MAX_STATES: u64 = 256;
const MAX_FILE: u64 = 16 * 1024 * 1024 * 1024;
struct Options {
    keep_data: bool,
    prefix: Option<PathBuf>,
}
pub(crate) fn is_command(rest: &[String]) -> bool {
    rest.first().is_some_and(|word| word == "uninstall")
}
fn parse(rest: &[String]) -> Result<Options, CliError> {
    if !is_command(rest) {
        return Err(CliError::usage(HELP));
    }
    let mut keep_data = false;
    let mut prefix = None;
    let mut index = 1;
    while index < rest.len() {
        match rest[index].as_str() {
            "--keep-data" if !keep_data => {
                keep_data = true;
                index += 1;
            }
            "--install-prefix" if prefix.is_none() => {
                let value = rest.get(index + 1).ok_or_else(|| CliError::usage(HELP))?;
                if value.trim().is_empty()
                    || value.starts_with('-')
                    || value.chars().any(char::is_control)
                    || Path::new(value)
                        .components()
                        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
                {
                    return Err(CliError::usage(HELP));
                }
                prefix = Some(package_installation::absolute(Path::new(value))?);
                index += 2;
            }
            _ => return Err(CliError::usage(HELP)),
        }
    }
    Ok(Options { keep_data, prefix })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    Deadline,
    IdentityChanged,
    MaintenanceConflict,
    EmissionDrainPending,
    SupervisorDrainPending,
    BackgroundDrainPending,
    PurgeOwnerDrainPending,
    CatalogDrainPending,
    WriterDrainPending,
    HostInventoryUnverified,
    HostConfigurationRetained,
    NativeInventoryUnverified,
    NativeConfigurationRetained,
    PathConfigurationRetained,
    PurgePrerequisitePending,
    CacheCleanupPending,
    CorpusCleanupPending,
    BackupCleanupPending,
    UnclassifiedOwnedArtifact,
    FileChanged,
    FileLocked,
    SourceOverlap,
    ControlHandleDrainRequired,
    ControlCleanupPending,
    OwnedAfterExitHelperRequired,
    AfterExitCleanupPending,
    PrivateMetadataCleanupPending,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    status: String,
    keep_data: bool,
    installation_bound: bool,
    maintenance_fenced: bool,
    emission_drained: bool,
    supervisor_drained: bool,
    background_drained: bool,
    purge_owner_drained: bool,
    catalog_drained: bool,
    writer_drained: bool,
    corpus_removed: bool,
    catalog_and_policy_retained: bool,
    continuation_cache_cleared: bool,
    host_nodes_removed: u64,
    host_nodes_retained: u64,
    native_registration_removed: bool,
    native: Option<Value>,
    path: Option<Value>,
    backups_removed: u64,
    private_cleanup_receipt_recorded: bool,
    control_cleanup_pending: bool,
    package_cleanup_pending: bool,
    cleanup_pending: bool,
    #[serde(default)]
    after_exit_cleanup_pending: bool,
    #[serde(default)]
    private_metadata_cleanup_pending: bool,
    #[serde(default)]
    preserved_private_artifacts: u64,
    #[serde(default)]
    recovery_entry_recorded: bool,
    reasons: Vec<Reason>,
    next_action: String,
}
impl Report {
    fn new(keep_data: bool) -> Self {
        Self {
            status: "pending_cleanup".into(),
            keep_data,
            installation_bound: true,
            maintenance_fenced: false,
            emission_drained: false,
            supervisor_drained: false,
            background_drained: false,
            purge_owner_drained: false,
            catalog_drained: false,
            writer_drained: false,
            corpus_removed: false,
            catalog_and_policy_retained: keep_data,
            continuation_cache_cleared: false,
            host_nodes_removed: 0,
            host_nodes_retained: 0,
            native_registration_removed: false,
            native: None,
            path: None,
            backups_removed: 0,
            private_cleanup_receipt_recorded: false,
            control_cleanup_pending: !keep_data,
            package_cleanup_pending: true,
            cleanup_pending: true,
            after_exit_cleanup_pending: true,
            private_metadata_cleanup_pending: !keep_data,
            preserved_private_artifacts: 0,
            recovery_entry_recorded: false,
            reasons: Vec::new(),
            next_action: "retain_private_receipts_and_finish_verified_owned_cleanup".into(),
        }
    }
    fn pending(&mut self, reason: Reason) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
    fn outcome(&self) -> Outcome {
        if self.cleanup_pending {
            Outcome::Partial
        } else {
            Outcome::Success
        }
    }
}
/// Relative private per-file plan for the final helper; never protocol output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedFile {
    pub(crate) relative: String,
    pub(crate) digest: String,
    pub(crate) size: u64,
    pub(crate) identity: (u64, u64),
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GroupKind {
    Corpus,
    Cache,
    Backup,
    Control,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovalGroup {
    kind: GroupKind,
    files: Vec<OwnedFile>,
    removed: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    schema: String,
    installation_id: String,
    prefix_root: String,
    data_root: String,
    catalog_name: String,
    nonce: String,
    keep_data: bool,
}
/// Read-only handoff to final control-lifetime/after-exit cleanup. The stored
/// plan never grants control.db or live executable deletion authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeferredCleanup {
    schema: String,
    owner: Owner,
    sequence: u64,
    catalog_incarnation: String,
    catalog_file_identity: (u64, u64),
    retirement_intent_captured: bool,
    #[serde(default)]
    control_retired: bool,
    #[serde(default)]
    purge_prerequisite_complete: bool,
    #[serde(default)]
    terminal_policy: Option<TerminalPolicy>,
    #[serde(default)]
    after_exit: Option<managed_uninstall_cleanup::HelperPlan>,
    #[serde(default)]
    private_metadata: managed_uninstall_cleanup::PrivateMetadata,
    package_manifest_sha256: String,
    pub(crate) package_files: Vec<OwnedFile>,
    groups: Vec<RemovalGroup>,
    report: Report,
}
/// Private snapshot used only after the real control connection is closed.
/// This preserves every source locator (including disabled selections/denies)
/// so terminal removal never gains source access from an absent control.db.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalPolicy {
    control_seq: i64,
    policy_epoch: i64,
    regions: Vec<TerminalRegion>,
    control_file_identity: (u64, u64),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalRegion {
    locator: String,
    recursive: bool,
}
impl TerminalPolicy {
    fn capture(policy: &ReadPolicy, root: &Path) -> Result<Self, Reason> {
        let regions = policy
            .selections
            .iter()
            .map(|selection| &selection.region)
            .chain(
                policy
                    .exclusions
                    .iter()
                    .filter_map(|exclusion| match &exclusion.region {
                        ExcludedRegion::Locator(region) => Some(region),
                        ExcludedRegion::SourceIdentity { .. } => None,
                    }),
            )
            .map(|region| TerminalRegion {
                locator: region.locator.as_str().into(),
                recursive: region.kind == RootKind::Root,
            })
            .collect();
        let file = platform::open_file(&SqliteControlStore::path(root))
            .map_err(|_| Reason::ControlCleanupPending)?;
        Ok(Self {
            control_seq: policy.control_seq.get(),
            policy_epoch: policy.policy_epoch.get(),
            regions,
            control_file_identity: platform::identity(&file)
                .map_err(|_| Reason::ControlCleanupPending)?,
        })
    }
    fn validate(&self) -> Result<(), Reason> {
        if self.control_seq < 0 || self.policy_epoch < 0 || self.regions.len() > MAX_ENTRIES {
            return Err(Reason::IdentityChanged);
        }
        for region in &self.regions {
            CanonicalLocator::parse(&region.locator).map_err(|_| Reason::IdentityChanged)?;
        }
        Ok(())
    }
    fn overlaps(&self, path: &Path) -> Result<bool, Reason> {
        self.validate()?;
        let locator = CanonicalLocator::from_path(path).map_err(|_| Reason::SourceOverlap)?;
        for region in &self.regions {
            if CanonicalLocator::parse(&region.locator)
                .map_err(|_| Reason::SourceOverlap)?
                .denies(
                    &locator,
                    if region.recursive {
                        RootKind::Root
                    } else {
                        RootKind::Exact
                    },
                )
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
/// Held across the close of the final caller-owned control connection. The
/// writer lease and all real reader/owner locks survive every terminal step.
struct CleanupGuards {
    emission: ExclusiveGuard,
    supervisor: ExclusiveGuard,
    background: ExclusiveGuard,
    purge: ExclusiveGuard,
    catalog_handles: ExclusiveGuard,
    _writer: WriterLease,
    policy_owner: ExclusiveGuard,
}
impl CleanupGuards {
    fn retirement(&self) -> RetirementDrainGuards<'_> {
        RetirementDrainGuards {
            policy_owner: &self.policy_owner,
            emission: &self.emission,
            catalog_handles: &self.catalog_handles,
            background: &self.background,
            supervisor: &self.supervisor,
            purge: &self.purge,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementMarker {
    schema: String,
    control_root_id: String,
    prefix_root_id: String,
    installation_id: String,
    catalog_incarnation: String,
    operation_id: String,
    control_seq: i64,
    policy_epoch: i64,
}
struct Journal {
    root: PathBuf,
    prefix: PathBuf,
    catalog: PathBuf,
    prefix_identity: RootIdentity,
    data_identity: RootIdentity,
    _directory: File,
    state: DeferredCleanup,
    receipt_digest: Option<String>,
}
fn error(code: CanonicalCode) -> CliError {
    ProtocolError::new(code, "owned uninstall could not verify private state; retain current policy and installation receipts").into()
}
fn port(value: PortError) -> CliError {
    error(match value {
        PortError::InvalidRequest(_) => CanonicalCode::CapabilityNotSupported,
        PortError::NotFound(_) => CanonicalCode::NotFound,
        PortError::WriterBusy(_) => CanonicalCode::WriterBusy,
        PortError::DeadlineExceeded(_) => CanonicalCode::DeadlineExceeded,
        PortError::SchemaIncompatible(_) => CanonicalCode::SchemaIncompatible,
        PortError::GenerationMismatch(_) => CanonicalCode::GenerationMismatch,
        PortError::SnapshotChanged(_) => CanonicalCode::SourceChanged,
        PortError::SourceIo(_) => CanonicalCode::SourceIo,
        PortError::Backend(_) => CanonicalCode::CatalogError,
    })
}
fn time(end: Instant) -> Result<(), Reason> {
    if Instant::now() >= end {
        Err(Reason::Deadline)
    } else {
        Ok(())
    }
}
fn new_id() -> Result<String, CliError> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| error(CanonicalCode::Internal))?;
    Ok(format!(
        "uninstall_{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}
fn checked_root(path: &Path) -> Result<RootIdentity, CliError> {
    package_installation::ordinary(path)?;
    platform::validate_private(path).map_err(|_| error(CanonicalCode::CapabilityNotSupported))?;
    RootIdentity::read(path).map_err(port)
}
fn read_owner(root: &Path) -> Result<Option<Owner>, CliError> {
    let Some(bytes) = update_state::read(&root.join("owner.json"), 8192)? else {
        return Ok(None);
    };
    let owner: Owner =
        serde_json::from_slice(&bytes).map_err(|_| error(CanonicalCode::SchemaIncompatible))?;
    if owner.schema != OWNER_SCHEMA
        || ControlId::parse(&owner.installation_id).is_err()
        || ControlId::parse(&owner.nonce).is_err()
        || !package_installation::safe_member(&owner.catalog_name)
        || owner.catalog_name.contains('/')
    {
        return Err(error(CanonicalCode::SchemaIncompatible));
    }
    Ok(Some(owner))
}
fn load_state(
    root: &Path,
    owner: &Owner,
    end: Instant,
) -> Result<Option<DeferredCleanup>, CliError> {
    let mut states = BTreeMap::new();
    for (count, entry) in fs::read_dir(root)
        .map_err(|_| error(CanonicalCode::SourceIo))?
        .enumerate()
    {
        time(end).map_err(|_| error(CanonicalCode::WriterBusy))?;
        if count >= MAX_ENTRIES {
            return Err(error(CanonicalCode::SchemaIncompatible));
        }
        let entry = entry.map_err(|_| error(CanonicalCode::SourceIo))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(error(CanonicalCode::SchemaIncompatible));
        };
        if name == "owner.json" {
            continue;
        }
        if name == "helper" {
            checked_root(&entry.path())?;
            continue;
        }
        let number = name
            .strip_prefix("state-")
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|number| number.len() == 6)
            .and_then(|number| number.parse::<u64>().ok())
            .filter(|number| *number > 0 && *number <= MAX_STATES)
            .ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
        states.insert(number, entry.path());
    }
    let Some((sequence, path)) = states.last_key_value() else {
        return Ok(None);
    };
    if states.keys().copied().ne(1..=*sequence) {
        return Err(error(CanonicalCode::SchemaIncompatible));
    }
    let bytes = update_state::read(path, INVENTORY_LIMIT)?
        .ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
    let state: DeferredCleanup =
        serde_json::from_slice(&bytes).map_err(|_| error(CanonicalCode::SchemaIncompatible))?;
    if state.schema != STATE_SCHEMA || state.owner != *owner || state.sequence != *sequence {
        return Err(error(CanonicalCode::SchemaIncompatible));
    }
    for file in state
        .package_files
        .iter()
        .chain(state.groups.iter().flat_map(|group| &group.files))
    {
        if !package_installation::safe_member(&file.relative)
            || !package_installation::hex(&file.digest, 64)
            || file.size > MAX_FILE
        {
            return Err(error(CanonicalCode::SchemaIncompatible));
        }
    }
    if let Some(plan) = &state.after_exit {
        plan.validate(&state)
            .map_err(|_| error(CanonicalCode::SchemaIncompatible))?;
    }
    Ok(Some(state))
}
/// Read-only handoff. Callers must independently obtain all live drain proofs.
pub(crate) fn read_deferred_cleanup(
    prefix: &Path,
    catalog: &Path,
    end: Instant,
) -> Result<Option<DeferredCleanup>, CliError> {
    time(end).map_err(|_| error(CanonicalCode::WriterBusy))?;
    let root = prefix.join("uninstall");
    match fs::symlink_metadata(&root) {
        Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error(CanonicalCode::SourceIo)),
        Ok(_) => {}
    }
    checked_root(&root)?;
    let owner = read_owner(&root)?.ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
    let data = catalog
        .parent()
        .ok_or_else(|| error(CanonicalCode::InvalidRequest))?;
    package_installation::ordinary(prefix)?;
    if owner.prefix_root
        != RootIdentity::read(prefix)
            .map_err(port)?
            .control_id()
            .as_str()
        || owner.data_root != checked_root(data)?.control_id().as_str()
        || catalog.file_name().and_then(|name| name.to_str()) != Some(owner.catalog_name.as_str())
    {
        return Err(error(CanonicalCode::CapabilityNotSupported));
    }
    let state = load_state(&root, &owner, end)?;
    if retirement_present(data)? {
        let state = state.ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
        validate_retired_receipt(data, &state, end)?;
        return Ok(Some(state));
    }
    let control =
        SqliteControlStore::open_current_read_only_with_deadline(data, end).map_err(port)?;
    let status = control
        .with_runtime_deadline(end, || control.status())
        .map_err(port)?;
    if owner.installation_id != status.policy.installation_id.as_str() {
        return Err(error(CanonicalCode::CapabilityNotSupported));
    }
    if state
        .as_ref()
        .is_some_and(|state| state.report.maintenance_fenced)
        && (status.policy.maintenance.state != MaintenanceState::Uninstalling
            || status
                .policy
                .maintenance
                .owner
                .as_ref()
                .map(ControlId::as_str)
                != Some(owner.nonce.as_str()))
    {
        return Err(error(CanonicalCode::GenerationMismatch));
    }
    Ok(state)
}
fn retirement_present(root: &Path) -> Result<bool, CliError> {
    let mut present = false;
    for name in [RETIREMENT_MARKER, RETIREMENT_PENDING_MARKER] {
        match fs::symlink_metadata(root.join(name)) {
            Ok(_) => present = true,
            Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error(CanonicalCode::SourceIo)),
        }
    }
    Ok(present)
}
fn validate_retired_receipt(
    root: &Path,
    state: &DeferredCleanup,
    end: Instant,
) -> Result<(), CliError> {
    time(end).map_err(|_| error(CanonicalCode::WriterBusy))?;
    let published = update_state::read(&root.join(RETIREMENT_MARKER), 2048)?;
    let pending = update_state::read(&root.join(RETIREMENT_PENDING_MARKER), 2048)?;
    let bytes = match (published, pending) {
        (Some(bytes), None) | (None, Some(bytes)) => bytes,
        _ => return Err(error(CanonicalCode::SchemaIncompatible)),
    };
    let marker: RetirementMarker =
        serde_json::from_slice(&bytes).map_err(|_| error(CanonicalCode::SchemaIncompatible))?;
    let policy = state
        .terminal_policy
        .as_ref()
        .ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
    policy
        .validate()
        .map_err(|_| error(CanonicalCode::SchemaIncompatible))?;
    if !state.retirement_intent_captured
        || state.owner.keep_data
        || !state.report.maintenance_fenced
        || marker.schema != "asg.control-retirement/v1"
        || marker.installation_id != state.owner.installation_id
        || marker.catalog_incarnation != state.catalog_incarnation
        || marker.operation_id != state.owner.nonce
        || marker.control_root_id != state.owner.data_root
        || marker.prefix_root_id != state.owner.prefix_root
        || marker.control_seq != policy.control_seq
        || marker.policy_epoch != policy.policy_epoch
    {
        return Err(error(CanonicalCode::GenerationMismatch));
    }
    Ok(())
}

impl Journal {
    fn open(
        install: &Installation,
        catalog: &Path,
        control: &SqliteControlStore,
        keep_data: bool,
        incarnation: String,
        catalog_file_identity: (u64, u64),
        end: Instant,
    ) -> Result<Self, CliError> {
        let root = install.prefix.join("uninstall");
        let data = catalog
            .parent()
            .ok_or_else(|| error(CanonicalCode::InvalidRequest))?;
        let prefix_identity = RootIdentity::read(&install.prefix).map_err(port)?;
        let data_identity = checked_root(data)?;
        let installation = control.status().map_err(port)?.policy.installation_id;
        let existing = match fs::symlink_metadata(&root) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(error(CanonicalCode::SourceIo)),
        };
        if !existing {
            platform::create_private_directory(&root)
                .map_err(|_| error(CanonicalCode::SourceIo))?;
        }
        checked_root(&root)?;
        let mut owner = Owner {
            schema: OWNER_SCHEMA.into(),
            installation_id: installation.as_str().into(),
            prefix_root: prefix_identity.control_id().as_str().into(),
            data_root: data_identity.control_id().as_str().into(),
            catalog_name: catalog
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| error(CanonicalCode::InvalidRequest))?
                .into(),
            nonce: new_id()?,
            keep_data,
        };
        if existing {
            let recorded =
                read_owner(&root)?.ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
            owner.nonce.clone_from(&recorded.nonce);
            if owner != recorded {
                return Err(error(CanonicalCode::CapabilityNotSupported));
            }
        } else {
            update_state::write_new(
                &root.join("owner.json"),
                &serde_json::to_vec(&owner).map_err(|_| error(CanonicalCode::Internal))?,
            )?;
        }
        let state = match load_state(&root, &owner, end)? {
            Some(state) => state,
            None => DeferredCleanup {
                schema: STATE_SCHEMA.into(),
                owner,
                sequence: 0,
                catalog_incarnation: incarnation,
                catalog_file_identity,
                retirement_intent_captured: false,
                control_retired: false,
                purge_prerequisite_complete: false,
                terminal_policy: None,
                after_exit: None,
                private_metadata: Default::default(),
                package_manifest_sha256: install.package_files_sha256.clone(),
                package_files: Vec::new(),
                groups: Vec::new(),
                report: Report::new(keep_data),
            },
        };
        let mut journal = Self {
            root: root.clone(),
            prefix: install.prefix.clone(),
            catalog: catalog.into(),
            prefix_identity,
            data_identity,
            _directory: platform::directory(&root).map_err(|_| error(CanonicalCode::SourceIo))?,
            state,
            receipt_digest: None,
        };
        if journal.state.sequence == 0 {
            journal.save(end)?;
        } else {
            journal.capture_receipt()?;
        }
        Ok(journal)
    }
    fn resume(
        install: &Installation,
        catalog: &Path,
        state: DeferredCleanup,
        end: Instant,
    ) -> Result<Self, CliError> {
        let root = install.prefix.join("uninstall");
        let data = catalog
            .parent()
            .ok_or_else(|| error(CanonicalCode::InvalidRequest))?;
        let mut journal = Self {
            prefix_identity: RootIdentity::read(&install.prefix).map_err(port)?,
            data_identity: checked_root(data)?,
            _directory: platform::directory(&root).map_err(|_| error(CanonicalCode::SourceIo))?,
            root,
            prefix: install.prefix.clone(),
            catalog: catalog.into(),
            state,
            receipt_digest: None,
        };
        journal.capture_receipt()?;
        journal
            .validate_roots(end)
            .map_err(|_| error(CanonicalCode::SourceChanged))?;
        validate_retired_receipt(data, &journal.state, end)?;
        Ok(journal)
    }
    fn validate(&self, control: &SqliteControlStore, end: Instant) -> Result<ReadPolicy, Reason> {
        self.validate_roots(end)?;
        if RootIdentity::read(&self.prefix).map_err(|_| Reason::IdentityChanged)?
            != self.prefix_identity
            || RootIdentity::read(self.catalog.parent().ok_or(Reason::IdentityChanged)?)
                .map_err(|_| Reason::IdentityChanged)?
                != self.data_identity
        {
            return Err(Reason::IdentityChanged);
        }
        let fresh = SqliteControlStore::open_read_only(
            self.catalog.parent().ok_or(Reason::IdentityChanged)?,
            &ControlId::parse(&self.state.owner.installation_id)
                .map_err(|_| Reason::IdentityChanged)?,
        )
        .map_err(|_| Reason::IdentityChanged)?;
        let policy = fresh
            .read_policy(RequestIntersection::Selected)
            .map_err(|_| Reason::IdentityChanged)?;
        if policy.installation_id
            != control
                .status()
                .map_err(|_| Reason::IdentityChanged)?
                .policy
                .installation_id
        {
            return Err(Reason::IdentityChanged);
        }
        if self.state.report.maintenance_fenced
            && (policy.maintenance.state != MaintenanceState::Uninstalling
                || policy.maintenance.owner.as_ref().map(ControlId::as_str)
                    != Some(self.state.owner.nonce.as_str()))
        {
            return Err(Reason::MaintenanceConflict);
        }
        Ok(policy)
    }
    fn validate_roots(&self, end: Instant) -> Result<(), Reason> {
        time(end)?;
        package_installation::ordinary(&self.prefix).map_err(|_| Reason::IdentityChanged)?;
        if RootIdentity::read(&self.prefix).map_err(|_| Reason::IdentityChanged)?
            != self.prefix_identity
            || checked_root(self.catalog.parent().ok_or(Reason::IdentityChanged)?)
                .map_err(|_| Reason::IdentityChanged)?
                != self.data_identity
            || platform::identity(
                &platform::directory(&self.root).map_err(|_| Reason::IdentityChanged)?,
            )
            .map_err(|_| Reason::IdentityChanged)?
                != platform::identity(&self._directory).map_err(|_| Reason::IdentityChanged)?
            || read_owner(&self.root)
                .map_err(|_| Reason::IdentityChanged)?
                .as_ref()
                != Some(&self.state.owner)
        {
            return Err(Reason::IdentityChanged);
        }
        self.validate_receipt()
    }
    fn receipt_path(&self) -> PathBuf {
        self.root
            .join(format!("state-{:06}.json", self.state.sequence))
    }
    fn capture_receipt(&mut self) -> Result<(), CliError> {
        let bytes = update_state::read(&self.receipt_path(), INVENTORY_LIMIT)?
            .ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
        self.receipt_digest = Some(format!("{:x}", Sha256::digest(&bytes)));
        Ok(())
    }
    fn validate_receipt(&self) -> Result<(), Reason> {
        let Some(expected) = &self.receipt_digest else {
            return Ok(());
        };
        let bytes = update_state::read(&self.receipt_path(), INVENTORY_LIMIT)
            .map_err(|_| Reason::IdentityChanged)?
            .ok_or(Reason::IdentityChanged)?;
        if format!("{:x}", Sha256::digest(&bytes)) != *expected {
            return Err(Reason::IdentityChanged);
        }
        Ok(())
    }
    fn save(&mut self, end: Instant) -> Result<(), CliError> {
        self.validate_roots(end)
            .map_err(|_| error(CanonicalCode::SourceChanged))?;
        if RootIdentity::read(&self.prefix).map_err(port)? != self.prefix_identity
            || RootIdentity::read(
                self.catalog
                    .parent()
                    .ok_or_else(|| error(CanonicalCode::InvalidRequest))?,
            )
            .map_err(port)?
                != self.data_identity
            || self.state.sequence >= MAX_STATES
        {
            return Err(error(CanonicalCode::SchemaIncompatible));
        }
        self.state.sequence += 1;
        self.state.report.private_cleanup_receipt_recorded = true;
        let bytes = serde_json::to_vec(&self.state).map_err(|_| error(CanonicalCode::Internal))?;
        if bytes.len() as u64 > INVENTORY_LIMIT {
            return Err(error(CanonicalCode::SchemaIncompatible));
        }
        update_state::write_new(&self.receipt_path(), &bytes)?;
        self.capture_receipt()
    }
    fn save_before_deadline(&mut self, end: Instant) -> Result<(), CliError> {
        // No replacement budget. The previously flushed intent/fence remains.
        if Instant::now() < end {
            self.save(end)
        } else {
            Ok(())
        }
    }
}
pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    if is_command(rest) && matches!(&rest[1..], [flag] if flag == "--help" || flag == "-h") {
        emit_help("uninstall", HELP, mode, request_id);
        return Ok(Outcome::Success);
    }
    let started = Instant::now();
    let options = parse(rest)?;
    let recovered = if let Some(prefix) = options.prefix.as_deref() {
        let catalog = package_installation::absolute(Path::new(db))?;
        managed_uninstall_cleanup::recover_public(
            &catalog,
            prefix,
            options.keep_data,
            started + BUDGET,
        )?
    } else {
        None
    };
    let was_recovered = recovered.is_some();
    let mut report = if let Some(report) = recovered {
        report
    } else {
        execute(
            db,
            options,
            started + BUDGET,
            &mut |prefix| package_installation::installation(prefix),
            &mut local_execute,
            &mut |catalog, prefix, end| {
                serde_json::to_value(path_command::remove_owned(catalog, prefix, end))
                    .map_err(|_| error(CanonicalCode::Internal))
            },
        )?
    };
    if report.private_cleanup_receipt_recorded
        && report.after_exit_cleanup_pending
        && !was_recovered
        && let Ok(updated) = managed_uninstall_cleanup::schedule(
            db,
            options_prefix_for_handoff(rest)?,
            started + BUDGET,
        )
    {
        report = updated;
    }
    let outcome = report.outcome();
    emit_result(
        "uninstall",
        mode,
        outcome,
        serde_json::to_value(report).map_err(|_| error(CanonicalCode::Internal))?,
        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        &Page::default(),
        &[],
        request_id,
        RetrievalMode::Lexical,
    );
    Ok(outcome)
}
fn options_prefix_for_handoff(rest: &[String]) -> Result<Option<PathBuf>, CliError> {
    Ok(parse(rest)?.prefix)
}
fn local_execute(
    program: &Path,
    args: &[OsString],
    end: Instant,
) -> Result<LocalCapture, ManagerError> {
    let args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    capture_local(program, &args, end).map_err(|error| {
        ManagerError::from(match error.code {
            setup_hosts::SetupHostsErrorCode::ProbeTimeout => native_manager::ErrorCode::Timeout,
            setup_hosts::SetupHostsErrorCode::Io
            | setup_hosts::SetupHostsErrorCode::InvalidPath => {
                native_manager::ErrorCode::Unavailable
            }
            _ => native_manager::ErrorCode::Failed,
        })
    })
}
fn acquire(
    root: &Path,
    kind: LockKind,
    end: Instant,
    reason: Reason,
) -> Result<ExclusiveGuard, Reason> {
    loop {
        time(end)?;
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return Ok(guard),
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
            ),
            Err(_) => return Err(reason),
        }
    }
}
fn writer(root: &Path, end: Instant) -> Result<WriterLease, Reason> {
    loop {
        time(end)?;
        match WriterLease::try_acquire(root) {
            Ok(lease) => return Ok(lease),
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
            ),
            Err(_) => return Err(Reason::WriterDrainPending),
        }
    }
}
fn fence(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    journal: &mut Journal,
    end: Instant,
) -> Result<(), Reason> {
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    let owner =
        ControlId::parse(&journal.state.owner.nonce).map_err(|_| Reason::IdentityChanged)?;
    loop {
        journal.validate(control, end)?;
        let lock = acquire(
            root,
            LockKind::PolicyOwner,
            end,
            Reason::MaintenanceConflict,
        )?;
        let bound = control
            .bind_control_root(&lock)
            .map_err(|_| Reason::IdentityChanged)?;
        let status = control.status().map_err(|_| Reason::IdentityChanged)?;
        let maintenance = MaintenanceFence {
            state: MaintenanceState::Uninstalling,
            owner: Some(owner.clone()),
            phase: Some(MaintenancePhase::Quiescing),
        };
        match control.begin_maintenance(
            status.policy.control_seq,
            &owner,
            &bound,
            installation,
            maintenance,
        ) {
            Ok(_) => break,
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                if status
                    .policy
                    .maintenance
                    .owner
                    .as_ref()
                    .is_some_and(|prior| prior != &owner)
                {
                    return Err(Reason::MaintenanceConflict);
                }
            }
            Err(_) => return Err(Reason::MaintenanceConflict),
        }
    }
    journal.state.report.maintenance_fenced = true;
    loop {
        journal.validate(control, end)?;
        let lock = acquire(
            root,
            LockKind::PolicyOwner,
            end,
            Reason::MaintenanceConflict,
        )?;
        let _bound = control
            .bind_control_root(&lock)
            .map_err(|_| Reason::IdentityChanged)?;
        let status = control.status().map_err(|_| Reason::IdentityChanged)?;
        match control.set_autostart_enabled(status.policy.control_seq, false) {
            Ok(_) => return Ok(()),
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {}
            Err(_) => return Err(Reason::MaintenanceConflict),
        }
    }
}
type PathRemoval<'a> = dyn FnMut(&Path, &Path, Instant) -> Result<Value, CliError> + 'a;
fn execute(
    db: &str,
    options: Options,
    end: Instant,
    verify_install: &mut impl FnMut(Option<&Path>) -> Result<Installation, CliError>,
    native: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture, ManagerError>,
    remove_path: &mut PathRemoval<'_>,
) -> Result<Report, CliError> {
    time(end).map_err(|_| error(CanonicalCode::WriterBusy))?;
    let catalog = package_installation::absolute(Path::new(db))?;
    validate_catalog_path(&catalog).map_err(port)?;
    let root = catalog
        .parent()
        .ok_or_else(|| error(CanonicalCode::InvalidRequest))?;
    let _root_pin = platform::directory(root).map_err(|_| error(CanonicalCode::SourceIo))?;
    let install = verify_install(options.prefix.as_deref())?;
    if RootIdentity::read(&install.prefix).map_err(port)?
        == RootIdentity::read(root).map_err(port)?
    {
        return Err(error(CanonicalCode::CapabilityNotSupported));
    }
    if retirement_present(root)? {
        return resume_terminal(&install, &catalog, options.keep_data, end);
    }
    let control =
        SqliteControlStore::open_current_writable_with_deadline(root, end).map_err(port)?;
    let first_lock = update_state::acquire_installation_lock(&install.prefix, end)?;
    control
        .with_runtime_deadline(end, || {
            control.bind_installation(&install.prefix, &first_lock)
        })
        .map_err(port)?;
    let prior = read_deferred_cleanup(&install.prefix, &catalog, end)?;
    let status = control
        .with_runtime_deadline(end, || control.status())
        .map_err(port)?;
    let (incarnation, catalog_file_identity) = if let Some(state) = &prior {
        if state.owner.keep_data != options.keep_data {
            return Err(error(CanonicalCode::InvalidRequest));
        }
        (
            state.catalog_incarnation.clone(),
            state.catalog_file_identity,
        )
    } else {
        if status.policy.maintenance.state != MaintenanceState::Idle {
            return Err(error(CanonicalCode::WriterBusy));
        }
        let store = ManagedStore::open(&catalog, &control).map_err(port)?;
        let incarnation = store.incarnation().as_str().into();
        let file = platform::open_file(&catalog).map_err(|_| error(CanonicalCode::SourceIo))?;
        let identity = platform::identity(&file).map_err(|_| error(CanonicalCode::SourceIo))?;
        drop(file);
        drop(store);
        (incarnation, identity)
    };
    drop(first_lock);
    let mut path = prior
        .as_ref()
        .filter(|state| state.report.maintenance_fenced)
        .and_then(|state| state.report.path.clone());
    let lock = update_state::acquire_installation_lock(&install.prefix, end)?;
    let installation = control
        .bind_installation(&install.prefix, &lock)
        .map_err(port)?;
    let mut journal = Journal::open(
        &install,
        &catalog,
        &control,
        options.keep_data,
        incarnation,
        catalog_file_identity,
        end,
    )?;
    journal.state.report.path = path.clone();
    if journal.state.package_files.is_empty() {
        match package_plan(&install, &journal, &control, end) {
            Ok(plan) => journal.state.package_files = plan,
            Err(reason) => journal.state.report.pending(reason),
        }
    }
    journal.save(end)?;
    if !journal.state.report.maintenance_fenced {
        match purge_prerequisite(&control, &installation, &catalog, &install, end) {
            Ok(true) => journal.state.purge_prerequisite_complete = true,
            Ok(false) | Err(_) => journal
                .state
                .report
                .pending(Reason::PurgePrerequisitePending),
        }
    }
    if let Err(reason) = fence(&control, &installation, &mut journal, end) {
        journal.state.report.pending(reason);
        journal.save_before_deadline(end)?;
        return Ok(journal.state.report);
    }
    journal.save(end)?;
    // PATH is external state that setup can recreate. Mutate it only after the
    // durable Uninstalling fence is visible, and resume an unfinished PATH
    // transition on the same fenced journal.
    if path
        .as_ref()
        .is_none_or(|path| path["status"] != "complete" && path["reason"] != "unowned")
    {
        path = Some(remove_path(&catalog, &install.prefix, end)?);
        journal.state.report.path = path.clone();
    }
    if journal
        .state
        .report
        .path
        .as_ref()
        .is_some_and(|path| path["status"] != "complete" && path["reason"] != "unowned")
    {
        journal
            .state
            .report
            .pending(Reason::PathConfigurationRetained);
    }
    journal.save(end)?;
    let retirement = if options.keep_data {
        None
    } else if !journal.state.purge_prerequisite_complete {
        journal
            .state
            .report
            .pending(Reason::PurgePrerequisitePending);
        journal.save_before_deadline(end)?;
        return Ok(journal.state.report);
    } else {
        let operation = ControlId::parse(&journal.state.owner.nonce).map_err(port)?;
        match RetirementIntent::bind_with_deadline(
            &control,
            &catalog,
            &install.prefix,
            &lock,
            &operation,
            end,
        ) {
            Ok(intent) => {
                journal.state.retirement_intent_captured = true;
                Some(intent)
            }
            Err(_) => {
                journal
                    .state
                    .report
                    .pending(Reason::ControlHandleDrainRequired);
                journal.save_before_deadline(end)?;
                return Ok(journal.state.report);
            }
        }
    };
    journal.save_before_deadline(end)?;
    remove_native(&install, &control, &mut journal, native, end);
    remove_hosts(&install, &control, &mut journal, end);
    journal.save_before_deadline(end)?;
    match managed_uninstall_cleanup::classify_private(&install, &control, &journal, end) {
        Ok(metadata) => journal.state.private_metadata = metadata,
        Err(reason) => journal.state.report.pending(reason),
    }
    journal.save_before_deadline(end)?;
    let guards = match cleanup_data(&control, &mut journal, retirement.as_ref(), end) {
        Ok(guards) => Some(guards),
        Err(reason) => {
            journal.state.report.pending(reason);
            None
        }
    };
    if let (Some(intent), Some(guards)) = (retirement.as_ref(), guards.as_ref()) {
        match intent.refresh_with_deadline(&control, &guards.policy_owner, end) {
            Ok(refreshed) => {
                journal.state.terminal_policy = Some(
                    TerminalPolicy::capture(&control.status().map_err(port)?.policy, root)
                        .map_err(|_| error(CanonicalCode::CatalogError))?,
                );
                journal.save_before_deadline(end)?;
                drop(installation);
                drop(control);
                if let Err(reason) =
                    terminal_handoff(&mut journal, &refreshed, guards.retirement(), end)
                {
                    journal.state.report.pending(reason);
                }
            }
            Err(_) => journal
                .state
                .report
                .pending(Reason::PurgePrerequisitePending),
        }
    }
    if journal.state.after_exit.is_none() && !journal.state.package_files.is_empty() {
        match managed_uninstall_cleanup::prepare(&install, &mut journal, end) {
            Ok(()) => {}
            Err(reason) => journal.state.report.pending(reason),
        }
    }
    journal
        .state
        .report
        .pending(Reason::OwnedAfterExitHelperRequired);
    journal.save_before_deadline(end)?;
    Ok(journal.state.report)
}

fn purge_prerequisite(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    catalog: &Path,
    install: &Installation,
    end: Instant,
) -> Result<bool, Reason> {
    let root = catalog.parent().ok_or(Reason::IdentityChanged)?;
    let lock = acquire(
        root,
        managed_purge::purge_lock_kind().map_err(|_| Reason::PurgePrerequisitePending)?,
        end,
        Reason::PurgeOwnerDrainPending,
    )?;
    let owner = control
        .bind_purge_owner(
            &lock,
            ControlId::parse(&new_id().map_err(|_| Reason::PurgePrerequisitePending)?)
                .map_err(|_| Reason::PurgePrerequisitePending)?,
        )
        .map_err(|_| Reason::PurgePrerequisitePending)?;
    let jobs = control
        .purge_jobs()
        .map_err(|_| Reason::PurgePrerequisitePending)?;
    let inventory = crate::managed_purge::artifact_inventory(control, catalog, Some(install), end);
    let mut complete = inventory.is_ok();
    if jobs.iter().any(|job| job.state != PurgeState::Complete) {
        complete = inventory.is_ok_and(|inventory| {
            managed_purge::run_with_inventory(
                control,
                catalog,
                &owner,
                Some(installation),
                &inventory,
                crate::app_clock_ms(),
                end,
            )
            .is_ok_and(|report| report.complete())
        });
    }
    for backup in control
        .backup_records()
        .map_err(|_| Reason::BackupCleanupPending)?
    {
        time(end)?;
        match purge_backup(
            control,
            installation,
            &backup.backup_id,
            crate::app_clock_ms(),
            end,
        ) {
            Ok(
                PurgeOutcome::NotWithdrawn
                | PurgeOutcome::Purged {
                    artifact_removed: true,
                    ..
                },
            ) => {}
            _ => complete = false,
        }
    }
    Ok(complete)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostInventory {
    schema: String,
    #[serde(default)]
    binding: Option<InventoryBinding>,
    receipts: Vec<HostLocator>,
}
fn validate_inventory_binding(
    binding: Option<&InventoryBinding>,
    journal: &Journal,
    status: &ControlStatus,
) -> Result<(), Reason> {
    binding
        .ok_or(Reason::UnclassifiedOwnedArtifact)?
        .validate(journal.data_identity, status)
        .map_err(|_| Reason::UnclassifiedOwnedArtifact)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostLocator {
    host: Host,
    config_path: PathBuf,
    transaction_root: PathBuf,
    transaction_id: String,
    receipt_path: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeInventory {
    schema: String,
    #[serde(default)]
    binding: Option<InventoryBinding>,
    location: NativeLocation,
    journal_root: PathBuf,
    receipt: AutostartReceipt,
}
fn inventories(root: &Path, prefix: &str, end: Instant) -> Result<Vec<Vec<u8>>, Reason> {
    let mut records = Vec::new();
    for (count, entry) in fs::read_dir(root)
        .map_err(|_| Reason::IdentityChanged)?
        .enumerate()
    {
        time(end)?;
        if count >= MAX_ENTRIES {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
        let entry = entry.map_err(|_| Reason::IdentityChanged)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(prefix) && name.ends_with(".json") {
            records.push(
                update_state::read(&entry.path(), INVENTORY_LIMIT)
                    .map_err(|_| Reason::UnclassifiedOwnedArtifact)?
                    .ok_or(Reason::UnclassifiedOwnedArtifact)?,
            );
            if records.len() >= 256 {
                return Err(Reason::UnclassifiedOwnedArtifact);
            }
        }
    }
    Ok(records)
}
fn remove_hosts(
    install: &Installation,
    control: &SqliteControlStore,
    journal: &mut Journal,
    end: Instant,
) {
    let operation = (|| -> Result<(), Reason> {
        let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
        let registration = McpRegistration::new(
            install
                .launcher
                .to_str()
                .ok_or(Reason::HostInventoryUnverified)?
                .into(),
            vec![
                "--db".into(),
                journal
                    .catalog
                    .to_str()
                    .ok_or(Reason::HostInventoryUnverified)?
                    .into(),
                "mcp".into(),
            ],
        )
        .map_err(|_| Reason::HostInventoryUnverified)?;
        let mut locators = BTreeMap::new();
        for bytes in inventories(root, "setup-hosts-", end)? {
            let record: HostInventory =
                serde_json::from_slice(&bytes).map_err(|_| Reason::HostInventoryUnverified)?;
            validate_inventory_binding(
                record.binding.as_ref(),
                journal,
                &control.status().map_err(|_| Reason::IdentityChanged)?,
            )?;
            if record.schema != "asg.setup-host-inventory/v1" || record.receipts.len() > 256 {
                return Err(Reason::HostInventoryUnverified);
            }
            for locator in record.receipts {
                locators.insert(
                    (locator.config_path.clone(), locator.transaction_id.clone()),
                    locator,
                );
                if locators.len() >= 256 {
                    return Err(Reason::HostInventoryUnverified);
                }
            }
        }
        for locator in locators.into_values() {
            journal.validate(control, end)?;
            let locator = PrivateReceiptLocator {
                host: locator.host,
                config_path: locator.config_path,
                transaction_root: locator.transaction_root,
                transaction_id: locator.transaction_id,
                receipt_path: locator.receipt_path,
            };
            match setup_hosts::remove_owned_registration(&locator, &registration, end) {
                Ok(_) => journal.state.report.host_nodes_removed += 1,
                Err(error) => {
                    journal.state.report.host_nodes_retained += 1;
                    if error.code != host_config::ErrorCode::Unowned {
                        journal
                            .state
                            .report
                            .pending(Reason::HostConfigurationRetained);
                    }
                }
            }
        }
        Ok(())
    })();
    if let Err(reason) = operation {
        journal.state.report.pending(reason);
    }
}
fn native_root(location: &NativeLocation, data: &Path, installation: &str) -> PathBuf {
    match location {
        NativeLocation::WindowsRun { .. } => data.join("native-autostart"),
        NativeLocation::SystemdUser { directory }
        | NativeLocation::LaunchAgent { directory, .. } => {
            directory.join(format!(".asg-{installation}"))
        }
    }
}
fn remove_native(
    install: &Installation,
    control: &SqliteControlStore,
    journal: &mut Journal,
    native: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture, ManagerError>,
    end: Instant,
) {
    let operation = (|| -> Result<(), Reason> {
        let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
        let mut selected: Option<NativeInventory> = None;
        for bytes in inventories(root, "setup-autostart-", end)? {
            let record: NativeInventory =
                serde_json::from_slice(&bytes).map_err(|_| Reason::NativeInventoryUnverified)?;
            validate_inventory_binding(
                record.binding.as_ref(),
                journal,
                &control.status().map_err(|_| Reason::IdentityChanged)?,
            )?;
            if record.schema != "asg.setup-autostart-inventory/v1" {
                return Err(Reason::NativeInventoryUnverified);
            }
            if record.receipt.installation_id != journal.state.owner.installation_id {
                continue;
            }
            if record.journal_root
                != native_root(&record.location, root, &journal.state.owner.installation_id)
                || selected.as_ref().is_some_and(|prior| {
                    prior.location != record.location || prior.journal_root != record.journal_root
                })
            {
                return Err(Reason::NativeInventoryUnverified);
            }
            selected = Some(record);
        }
        let Some(record) = selected else {
            return Err(Reason::NativeInventoryUnverified);
        };
        let store = NativeAutostartStore::open(
            record.location,
            &record.journal_root,
            &journal.state.owner.installation_id,
        )
        .map_err(|_| Reason::NativeInventoryUnverified)?;
        let prior = store
            .latest_receipt()
            .map_err(|_| Reason::NativeInventoryUnverified)?
            .ok_or(Reason::NativeInventoryUnverified)?;
        if prior.state == ConfigurationState::Absent && prior.owned {
            journal.state.report.native_registration_removed = true;
            return Ok(());
        }
        if !prior.owned {
            return Err(Reason::NativeConfigurationRetained);
        }
        let (supervisor, digest) = install
            .supervisor
            .as_ref()
            .ok_or(Reason::NativeInventoryUnverified)?;
        let registration = SupervisorRegistration {
            supervisor: supervisor.clone(),
            supervisor_sha256: digest.clone(),
            catalog: journal.catalog.clone(),
        };
        let mut preflight = || {
            journal.validate(control, end).map(drop).map_err(|reason| {
                ManagerError::from(match reason {
                    Reason::Deadline => native_manager::ErrorCode::Timeout,
                    _ => native_manager::ErrorCode::Conflict,
                })
            })
        };
        let disabled = native_manager::disable_owned(
            &store,
            &prior,
            &registration,
            end,
            &mut preflight,
            native,
        )
        .map_err(|_| Reason::NativeConfigurationRetained)?;
        journal.state.report.native_registration_removed = !disabled.summary.registration_present;
        journal.state.report.native = serde_json::to_value(disabled.summary).ok();
        Ok(())
    })();
    if let Err(reason) = operation {
        journal.state.report.pending(reason);
    }
}
fn source_overlap(policy: &ReadPolicy, path: &Path) -> Result<bool, Reason> {
    let locator = CanonicalLocator::from_path(path).map_err(|_| Reason::SourceOverlap)?;
    Ok(policy.selections.iter().any(|selection| {
        selection
            .region
            .locator
            .denies(&locator, selection.region.kind)
    }) || policy
        .exclusions
        .iter()
        .any(|exclusion| match &exclusion.region {
            ExcludedRegion::Locator(region) => region.locator.denies(&locator, region.kind),
            ExcludedRegion::SourceIdentity { .. } => false,
        }))
}
fn owned_file(
    base: &Path,
    relative: &str,
    policy: &ReadPolicy,
    end: Instant,
) -> Result<OwnedFile, Reason> {
    owned_file_with_overlap(base, relative, &|path| source_overlap(policy, path), end)
}
fn owned_file_with_overlap(
    base: &Path,
    relative: &str,
    overlaps: &impl Fn(&Path) -> Result<bool, Reason>,
    end: Instant,
) -> Result<OwnedFile, Reason> {
    time(end)?;
    if !package_installation::safe_member(relative) {
        return Err(Reason::IdentityChanged);
    }
    let path = base.join(relative);
    package_installation::ordinary(&path).map_err(|_| Reason::IdentityChanged)?;
    if !path.starts_with(base) || overlaps(&path)? {
        return Err(Reason::SourceOverlap);
    }
    let mut file = platform::open_file(&path).map_err(|_| Reason::FileLocked)?;
    let metadata = file.metadata().map_err(|_| Reason::FileChanged)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err(Reason::FileChanged);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let mut information = std::mem::MaybeUninit::<
            windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
        >::uninit();
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                file.as_raw_handle() as _,
                information.as_mut_ptr(),
            )
        } == 0
            || unsafe { information.assume_init() }.nNumberOfLinks != 1
        {
            return Err(Reason::FileChanged);
        }
    }
    if metadata.len() > MAX_FILE {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    let identity = platform::identity(&file).map_err(|_| Reason::FileChanged)?;
    let mut digest = Sha256::new();
    let mut bytes = [0; 65536];
    let mut size = 0;
    while metadata.len() != 0 {
        time(end)?;
        let count = file.read(&mut bytes).map_err(|_| Reason::FileLocked)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_FILE {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
        digest.update(&bytes[..count]);
    }
    if size != metadata.len()
        || file.metadata().map_err(|_| Reason::FileChanged)?.len() != metadata.len()
        || platform::identity(&file).map_err(|_| Reason::FileChanged)? != identity
    {
        return Err(Reason::FileChanged);
    }
    Ok(OwnedFile {
        relative: relative.into(),
        digest: format!("{:x}", digest.finalize()),
        size,
        identity,
    })
}
fn remove_file_checked(
    base: &Path,
    proof: &OwnedFile,
    journal: &Journal,
    control: &SqliteControlStore,
    end: Instant,
) -> Result<(), Reason> {
    let policy = journal.validate(control, end)?;
    let path = base.join(&proof.relative);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Reason::FileLocked),
        Ok(_) => {}
    }
    let current = owned_file(base, &proof.relative, &policy, end)?;
    if current.identity != proof.identity
        || current.size != proof.size
        || current.digest != proof.digest
    {
        return Err(Reason::FileChanged);
    }
    journal.validate(control, end)?;
    package_installation::ordinary(&path).map_err(|_| Reason::IdentityChanged)?;
    if !fs::canonicalize(&path)
        .map_err(|_| Reason::IdentityChanged)?
        .starts_with(fs::canonicalize(base).map_err(|_| Reason::IdentityChanged)?)
    {
        return Err(Reason::IdentityChanged);
    }
    verified_remove_file(&path, &proof.identity)?;
    platform::sync_directory(path.parent().ok_or(Reason::IdentityChanged)?)
        .map_err(|_| Reason::FileLocked)?;
    Ok(())
}
/// Delete a verified file through a fresh handle whose identity still matches
/// the proof, closing the verify-then-delete pathname window.
fn verified_remove_file(path: &Path, identity: &(u64, u64)) -> Result<(), Reason> {
    #[cfg(windows)]
    {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::{
            Win32::Foundation::HANDLE,
            Win32::Storage::FileSystem::{
                self, DELETE, FILE_DISPOSITION_INFO, FILE_READ_ATTRIBUTES,
                SetFileInformationByHandle,
            },
        };
        let open_delete = || {
            fs::OpenOptions::new()
                .access_mode(DELETE | 0x8000_0000 | FILE_READ_ATTRIBUTES)
                .share_mode(FileSystem::FILE_SHARE_READ)
                .custom_flags(FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .map_err(|_| Reason::FileLocked)
        };
        let file = open_delete()?;
        if !file.metadata().map_err(|_| Reason::FileChanged)?.is_file()
            || platform::identity(&file).map_err(|_| Reason::FileChanged)? != *identity
        {
            return Err(Reason::FileChanged);
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        let mut result = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileSystem::FileDispositionInfo,
                &disposition as *const FILE_DISPOSITION_INFO as *const core::ffi::c_void,
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if result == 0 {
            // Nothing observes the pending disposition before this process
            // closes the failed handle, so retrying on the same inode is safe.
            drop(file);
            let retry = open_delete()?;
            if retry.metadata().map_err(|_| Reason::FileChanged)?.is_file()
                && platform::identity(&retry).map_err(|_| Reason::FileChanged)? == *identity
            {
                result = unsafe {
                    SetFileInformationByHandle(
                        retry.as_raw_handle() as HANDLE,
                        FileSystem::FileDispositionInfo,
                        &disposition as *const FILE_DISPOSITION_INFO as *const core::ffi::c_void,
                        std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                    )
                };
                // Windows defers a pending disposition until the last handle
                // closes; drop immediately so the removal is observable.
                drop(retry);
            }
        }
        if result == 0 {
            return Err(Reason::FileLocked);
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let file = platform::open_file(path).map_err(|_| Reason::FileLocked)?;
        let handle = file.metadata().map_err(|_| Reason::FileChanged)?;
        if !handle.is_file()
            || platform::identity(&file).map_err(|_| Reason::FileChanged)? != *identity
        {
            return Err(Reason::FileChanged);
        }
        let link = fs::symlink_metadata(path).map_err(|_| Reason::FileLocked)?;
        let name = fs::metadata(path).map_err(|_| Reason::FileLocked)?;
        use std::os::unix::fs::MetadataExt;
        if (link.dev(), link.ino()) != (name.dev(), name.ino())
            || (name.dev(), name.ino()) != (handle.dev(), handle.ino())
        {
            return Err(Reason::FileChanged);
        }
        drop(file);
        fs::remove_file(path).map_err(|_| Reason::FileLocked)?;
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (path, identity);
        Err(Reason::FileLocked)
    }
}
fn sqlite_group(
    journal: &Journal,
    control: &SqliteControlStore,
    path: &Path,
    application: u32,
    kind: GroupKind,
    end: Instant,
) -> Result<RemovalGroup, Reason> {
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Reason::IdentityChanged)?
        .to_str()
        .ok_or(Reason::IdentityChanged)?;
    let policy = journal.validate(control, end)?;
    let proof = owned_file(root, relative, &policy, end)?;
    if kind == GroupKind::Corpus && proof.identity != journal.state.catalog_file_identity {
        return Err(Reason::IdentityChanged);
    }
    let mut file = platform::open_file(path).map_err(|_| Reason::FileLocked)?;
    let mut header = [0; 100];
    file.read_exact(&mut header)
        .map_err(|_| Reason::FileChanged)?;
    if &header[..16] != b"SQLite format 3\0"
        || u32::from_be_bytes(header[68..72].try_into().map_err(|_| Reason::FileChanged)?)
            != application
    {
        return Err(Reason::FileChanged);
    }
    if kind == GroupKind::Corpus
        && u32::from_be_bytes(header[60..64].try_into().map_err(|_| Reason::FileChanged)?)
            != SCHEMA_VERSION as u32
    {
        return Err(Reason::FileChanged);
    }
    drop(file);
    let mut files = Vec::new();
    for suffix in ["-wal", "-shm", "-journal"] {
        let member = format!("{relative}{suffix}");
        match fs::symlink_metadata(root.join(&member)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Reason::FileLocked),
            Ok(_) => files.push(owned_file(root, &member, &policy, end)?),
        }
    }
    files.push(proof);
    if kind == GroupKind::Corpus {
        let marker = format!("{relative}.asg-managed-create");
        match fs::symlink_metadata(root.join(&marker)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Reason::FileLocked),
            Ok(_) => {
                let marker = owned_file(root, &marker, &policy, end)?;
                if marker.size != 0 {
                    return Err(Reason::FileChanged);
                }
                files.push(marker);
            }
        }
    }
    Ok(RemovalGroup {
        kind,
        files,
        removed: false,
    })
}
fn remove_group(
    control: &SqliteControlStore,
    journal: &mut Journal,
    index: usize,
    end: Instant,
) -> Result<(), Reason> {
    let group = journal.state.groups[index].clone();
    if group.removed {
        return Ok(());
    }
    for proof in &group.files {
        remove_file_checked(
            journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
            proof,
            journal,
            control,
            end,
        )?;
    }
    journal.state.groups[index].removed = true;
    match group.kind {
        GroupKind::Corpus => journal.state.report.corpus_removed = true,
        GroupKind::Cache => journal.state.report.continuation_cache_cleared = true,
        GroupKind::Backup => journal.state.report.backups_removed += 1,
        GroupKind::Control => return Err(Reason::ControlCleanupPending),
    }
    journal.save(end).map_err(|_| Reason::FileLocked)
}
fn package_plan(
    install: &Installation,
    journal: &Journal,
    control: &SqliteControlStore,
    end: Instant,
) -> Result<Vec<OwnedFile>, Reason> {
    let bytes = update_state::read(
        &install.prefix.join("PACKAGE-MANIFEST.tsv"),
        INVENTORY_LIMIT,
    )
    .map_err(|_| Reason::UnclassifiedOwnedArtifact)?
    .ok_or(Reason::UnclassifiedOwnedArtifact)?;
    if format!("{:x}", Sha256::digest(&bytes)) != install.package_files_sha256 {
        return Err(Reason::FileChanged);
    }
    let manifest = Manifest::parse(&bytes).map_err(|_| Reason::UnclassifiedOwnedArtifact)?;
    let policy = journal.validate(control, end)?;
    let mut names: BTreeSet<String> = manifest.members.keys().cloned().collect();
    names.extend(
        ["PACKAGE-MANIFEST.tsv", "package-install.json"]
            .into_iter()
            .map(str::to_owned),
    );
    for name in ["release.manifest.json", "SHA256SUMS"] {
        if fs::symlink_metadata(install.prefix.join(name)).is_ok() {
            names.insert(name.into());
        }
    }
    names
        .into_iter()
        .map(|relative| owned_file(&install.prefix, &relative, &policy, end))
        .collect()
}
fn cleanup_data(
    control: &SqliteControlStore,
    journal: &mut Journal,
    retirement: Option<&RetirementIntent<'_>>,
    end: Instant,
) -> Result<CleanupGuards, Reason> {
    let root = journal
        .catalog
        .parent()
        .ok_or(Reason::IdentityChanged)?
        .to_path_buf();
    journal.validate(control, end)?;
    let guards = drain_owners(journal, end)?;
    journal.validate(control, end)?;
    // Prepare proofs while the policy is live; default deletion waits until
    // every control handle is drained and the terminal marker is durable.
    if !journal.state.owner.keep_data && retirement.is_none() {
        return Err(Reason::PurgePrerequisitePending);
    }
    if !journal.state.owner.keep_data
        && !journal
            .state
            .groups
            .iter()
            .any(|group| group.kind == GroupKind::Corpus)
    {
        journal.state.groups.push(sqlite_group(
            journal,
            control,
            &journal.catalog,
            0x41534732,
            GroupKind::Corpus,
            end,
        )?);
        journal
            .save(end)
            .map_err(|_| Reason::CorpusCleanupPending)?;
    }
    if let Some(index) = journal
        .state
        .groups
        .iter()
        .position(|group| group.kind == GroupKind::Cache)
    {
        if journal.state.owner.keep_data {
            remove_group(control, journal, index, end)?;
        }
    } else {
        let cache = ManagedCache::at(&root, control).map_err(|_| Reason::CacheCleanupPending)?;
        let purge = cache
            .purge_all(control, &guards.emission, end)
            .map_err(|_| Reason::CacheCleanupPending)?;
        if !purge.wal_drained {
            return Err(Reason::CacheCleanupPending);
        }
        if ManagedCache::path(&root).exists() {
            journal.state.groups.push(sqlite_group(
                journal,
                control,
                &ManagedCache::path(&root),
                0x41534743,
                GroupKind::Cache,
                end,
            )?);
            journal.save(end).map_err(|_| Reason::CacheCleanupPending)?;
            if journal.state.owner.keep_data {
                remove_group(control, journal, journal.state.groups.len() - 1, end)?;
            }
        } else {
            journal.state.report.continuation_cache_cleared = true;
        }
    }
    if !journal.state.owner.keep_data {
        plan_backups(control, journal, end)?;
    }
    let _bound = control
        .bind_control_root(&guards.policy_owner)
        .map_err(|_| Reason::IdentityChanged)?;
    let policy = journal.validate(control, end)?;
    journal.state.terminal_policy = Some(TerminalPolicy::capture(&policy, &root)?);
    journal
        .save(end)
        .map_err(|_| Reason::ControlHandleDrainRequired)?;
    Ok(guards)
}
fn drain_owners(journal: &mut Journal, end: Instant) -> Result<CleanupGuards, Reason> {
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    journal.validate_roots(end)?;
    let emission = acquire(
        root,
        LockKind::PolicyEmission,
        end,
        Reason::EmissionDrainPending,
    )?;
    journal.state.report.emission_drained = true;
    let supervisor = native_manager::wait_supervisor_drained(root, journal.data_identity, end)
        .map_err(|_| Reason::SupervisorDrainPending)?;
    journal.state.report.supervisor_drained = true;
    let background = acquire(
        root,
        LockKind::Background,
        end,
        Reason::BackgroundDrainPending,
    )?;
    journal.state.report.background_drained = true;
    let purge = acquire(
        root,
        managed_purge::purge_lock_kind().map_err(|_| Reason::PurgeOwnerDrainPending)?,
        end,
        Reason::PurgeOwnerDrainPending,
    )?;
    journal.state.report.purge_owner_drained = true;
    let catalog_handles = acquire(
        root,
        LockKind::CatalogHandles,
        end,
        Reason::CatalogDrainPending,
    )?;
    journal.state.report.catalog_drained = true;
    let writer = writer(root, end)?;
    journal.state.report.writer_drained = true;
    let policy_owner = acquire(
        root,
        LockKind::PolicyOwner,
        end,
        Reason::ControlHandleDrainRequired,
    )?;
    journal.validate_roots(end)?;
    Ok(CleanupGuards {
        emission,
        supervisor,
        background,
        purge,
        catalog_handles,
        _writer: writer,
        policy_owner,
    })
}

fn plan_backups(
    control: &SqliteControlStore,
    journal: &mut Journal,
    end: Instant,
) -> Result<(), Reason> {
    let records = control
        .backup_records()
        .map_err(|_| Reason::BackupCleanupPending)?;
    let root = journal
        .catalog
        .parent()
        .ok_or(Reason::IdentityChanged)?
        .to_path_buf();
    for record in records {
        journal.validate(control, end)?;
        if journal.state.groups.iter().any(|group| {
            group.kind == GroupKind::Backup
                && group
                    .files
                    .iter()
                    .any(|file| file.relative == record.relative_locator)
        }) {
            continue;
        }
        if record.state == BackupState::PurgedByPolicy {
            continue;
        }
        if record.state != BackupState::Complete {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
        let verified = verify_backup_until(control, &record.backup_id, end)
            .map_err(|_| Reason::BackupCleanupPending)?;
        let policy = journal.validate(control, end)?;
        let file = owned_file(&root, &record.relative_locator, &policy, end)?;
        if file.digest != verified.metadata().digest || file.size != verified.metadata().size_bytes
        {
            return Err(Reason::FileChanged);
        }
        let parent = Path::new(&record.relative_locator)
            .parent()
            .ok_or(Reason::UnclassifiedOwnedArtifact)?;
        let sidecar = owned_file(
            &root,
            parent
                .join("manifest.json")
                .to_str()
                .ok_or(Reason::UnclassifiedOwnedArtifact)?,
            &policy,
            end,
        )?;
        journal.state.groups.push(RemovalGroup {
            kind: GroupKind::Backup,
            files: vec![file, sidecar],
            removed: false,
        });
        journal
            .save(end)
            .map_err(|_| Reason::BackupCleanupPending)?;
    }
    Ok(())
}
#[cfg(test)]
#[path = "uninstall_command_tests.rs"]
mod tests;

/// Caller has closed every owned control connection. The independent handle
/// gate and all owner drains now prove retirement; no control store is reopened.
fn terminal_handoff<'a>(
    journal: &mut Journal,
    intent: &RetirementIntent<'a>,
    drains: RetirementDrainGuards<'a>,
    end: Instant,
) -> Result<(), Reason> {
    if !journal.state.retirement_intent_captured || journal.state.owner.keep_data {
        return Err(Reason::ControlHandleDrainRequired);
    }
    let retirement = loop {
        journal.validate_roots(end)?;
        match intent.try_acquire_with_deadline(drains, end) {
            Ok(retirement) => break retirement,
            Err(PortError::WriterBusy(_)) => {
                if Instant::now() >= end {
                    return Err(Reason::ControlHandleDrainRequired);
                }
                std::thread::sleep(
                    Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
                );
            }
            Err(_) => return Err(Reason::IdentityChanged),
        }
    };
    time(end)?;
    retirement
        .publish_marker_with_deadline(end)
        .map_err(|_| Reason::ControlCleanupPending)?;
    journal.state.control_retired = true;
    journal
        .save(end)
        .map_err(|_| Reason::ControlCleanupPending)?;
    terminal_cleanup(journal, &retirement, end)
}
fn terminal_cleanup(
    journal: &mut Journal,
    retirement: &ControlRetirement<'_>,
    end: Instant,
) -> Result<(), Reason> {
    journal.validate_roots(end)?;
    retirement
        .validate_marker_with_deadline(end)
        .map_err(|_| Reason::IdentityChanged)?;
    let snapshot = journal
        .state
        .terminal_policy
        .clone()
        .ok_or(Reason::ControlCleanupPending)?;
    snapshot.validate()?;
    if journal.state.owner.keep_data {
        return Err(Reason::IdentityChanged);
    }
    for index in 0..journal.state.groups.len() {
        if journal.state.groups[index].kind != GroupKind::Control {
            terminal_remove_group(journal, index, retirement, &snapshot, end)?;
        }
    }
    if !journal.state.report.corpus_removed {
        return Err(Reason::CorpusCleanupPending);
    }
    if !journal
        .state
        .groups
        .iter()
        .any(|group| group.kind == GroupKind::Control)
    {
        let group = terminal_control_plan(journal, retirement, &snapshot, end)?;
        journal.state.groups.push(group);
        journal
            .save(end)
            .map_err(|_| Reason::ControlCleanupPending)?;
    }
    let index = journal
        .state
        .groups
        .iter()
        .position(|group| group.kind == GroupKind::Control)
        .ok_or(Reason::ControlCleanupPending)?;
    terminal_remove_group(journal, index, retirement, &snapshot, end)?;
    journal.state.report.control_cleanup_pending = false;
    journal.state.report.reasons.retain(|reason| {
        !matches!(
            reason,
            Reason::ControlHandleDrainRequired | Reason::ControlCleanupPending
        )
    });
    journal.save(end).map_err(|_| Reason::ControlCleanupPending)
}
fn terminal_control_plan(
    journal: &Journal,
    retirement: &ControlRetirement<'_>,
    snapshot: &TerminalPolicy,
    end: Instant,
) -> Result<RemovalGroup, Reason> {
    journal.validate_roots(end)?;
    retirement
        .validate_marker_with_deadline(end)
        .map_err(|_| Reason::IdentityChanged)?;
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    // The control adapter uses WAL. An unexplained rollback journal is never
    // classified by its suffix or silently discarded along with the database.
    match fs::symlink_metadata(root.join("control.db-journal")) {
        Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(Reason::ControlCleanupPending),
    }
    let database =
        owned_file_with_overlap(root, "control.db", &|path| snapshot.overlaps(path), end)?;
    if database.identity != snapshot.control_file_identity {
        return Err(Reason::FileChanged);
    }
    let mut file =
        platform::open_file(&SqliteControlStore::path(root)).map_err(|_| Reason::FileLocked)?;
    let mut header = [0; 100];
    file.read_exact(&mut header)
        .map_err(|_| Reason::FileChanged)?;
    if &header[..16] != b"SQLite format 3\0"
        || u32::from_be_bytes(header[68..72].try_into().map_err(|_| Reason::FileChanged)?)
            != 0x41534331
        || i64::from(u32::from_be_bytes(
            header[60..64].try_into().map_err(|_| Reason::FileChanged)?,
        )) != CONTROL_SCHEMA_VERSION
    {
        return Err(Reason::FileChanged);
    }
    drop(file);
    let mut files = Vec::new();
    for relative in ["control.db-wal", "control.db-shm"] {
        match fs::symlink_metadata(root.join(relative)) {
            Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Reason::FileLocked),
            Ok(_) => files.push(owned_file_with_overlap(
                root,
                relative,
                &|path| snapshot.overlaps(path),
                end,
            )?),
        }
    }
    files.push(database);
    Ok(RemovalGroup {
        kind: GroupKind::Control,
        files,
        removed: false,
    })
}
fn terminal_remove_group(
    journal: &mut Journal,
    index: usize,
    retirement: &ControlRetirement<'_>,
    snapshot: &TerminalPolicy,
    end: Instant,
) -> Result<(), Reason> {
    let group = journal.state.groups[index].clone();
    if group.removed {
        return Ok(());
    }
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    for proof in &group.files {
        terminal_validate_file(journal, proof, retirement, snapshot, end)?;
    }
    for proof in &group.files {
        terminal_validate_file(journal, proof, retirement, snapshot, end)?;
        if group.kind == GroupKind::Control {
            let leaf = match proof.relative.as_str() {
                "control.db" => RetiredControlFile::Database,
                "control.db-wal" => RetiredControlFile::Wal,
                "control.db-shm" => RetiredControlFile::SharedMemory,
                _ => return Err(Reason::UnclassifiedOwnedArtifact),
            };
            retirement
                .remove_control_file_with_deadline(leaf, end)
                .map_err(|_| Reason::ControlCleanupPending)?;
        } else {
            let path = root.join(&proof.relative);
            match fs::remove_file(&path) {
                Ok(()) => platform::sync_directory(path.parent().ok_or(Reason::IdentityChanged)?)
                    .map_err(|_| Reason::FileLocked)?,
                Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Reason::FileLocked),
            }
        }
        retirement
            .validate_marker_with_deadline(end)
            .map_err(|_| Reason::IdentityChanged)?;
    }
    journal.state.groups[index].removed = true;
    match group.kind {
        GroupKind::Corpus => journal.state.report.corpus_removed = true,
        GroupKind::Cache => journal.state.report.continuation_cache_cleared = true,
        GroupKind::Backup => journal.state.report.backups_removed += 1,
        GroupKind::Control => journal.state.report.control_cleanup_pending = false,
    }
    journal.save(end).map_err(|_| Reason::FileLocked)
}
fn terminal_validate_file(
    journal: &Journal,
    proof: &OwnedFile,
    retirement: &ControlRetirement<'_>,
    snapshot: &TerminalPolicy,
    end: Instant,
) -> Result<(), Reason> {
    journal.validate_roots(end)?;
    retirement
        .validate_marker_with_deadline(end)
        .map_err(|_| Reason::IdentityChanged)?;
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    match fs::symlink_metadata(root.join(&proof.relative)) {
        Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Reason::FileLocked),
        Ok(_) => {}
    }
    let actual =
        owned_file_with_overlap(root, &proof.relative, &|path| snapshot.overlaps(path), end)?;
    if actual.identity != proof.identity
        || actual.size != proof.size
        || actual.digest != proof.digest
    {
        return Err(Reason::FileChanged);
    }
    if !fs::canonicalize(root.join(&proof.relative))
        .map_err(|_| Reason::IdentityChanged)?
        .starts_with(fs::canonicalize(root).map_err(|_| Reason::IdentityChanged)?)
    {
        return Err(Reason::IdentityChanged);
    }
    journal.validate_roots(end)?;
    retirement
        .validate_marker_with_deadline(end)
        .map_err(|_| Reason::IdentityChanged)
}

fn resume_terminal(
    install: &Installation,
    catalog: &Path,
    keep_data: bool,
    end: Instant,
) -> Result<Report, CliError> {
    let state = read_deferred_cleanup(&install.prefix, catalog, end)?
        .ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
    if keep_data != state.owner.keep_data {
        return Err(error(CanonicalCode::InvalidRequest));
    }
    let lock = update_state::acquire_installation_lock(&install.prefix, end)?;
    let mut journal = Journal::resume(install, catalog, state, end)?;
    let result = (|| -> Result<(), Reason> {
        let guards = drain_owners(&mut journal, end)?;
        let installation = ControlId::parse(&journal.state.owner.installation_id)
            .map_err(|_| Reason::IdentityChanged)?;
        let incarnation = ControlId::parse(&journal.state.catalog_incarnation)
            .map_err(|_| Reason::IdentityChanged)?;
        let operation =
            ControlId::parse(&journal.state.owner.nonce).map_err(|_| Reason::IdentityChanged)?;
        let root = catalog.parent().ok_or(Reason::IdentityChanged)?;
        let retirement = loop {
            journal.validate_roots(end)?;
            match ControlRetirement::try_resume_with_deadline(
                root,
                &install.prefix,
                &lock,
                RetirementBinding {
                    installation: &installation,
                    catalog_incarnation: &incarnation,
                    operation: &operation,
                },
                guards.retirement(),
                end,
            ) {
                Ok(retirement) => break retirement,
                Err(PortError::WriterBusy(_)) => {
                    if Instant::now() >= end {
                        return Err(Reason::ControlHandleDrainRequired);
                    }
                    std::thread::sleep(
                        Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
                    );
                }
                Err(_) => return Err(Reason::IdentityChanged),
            }
        };
        journal.state.control_retired = true;
        journal
            .save(end)
            .map_err(|_| Reason::ControlCleanupPending)?;
        terminal_cleanup(&mut journal, &retirement, end)
    })();
    if let Err(reason) = result {
        journal.state.report.pending(reason);
    }
    journal
        .state
        .report
        .pending(Reason::OwnedAfterExitHelperRequired);
    journal.save_before_deadline(end)?;
    Ok(journal.state.report)
}
