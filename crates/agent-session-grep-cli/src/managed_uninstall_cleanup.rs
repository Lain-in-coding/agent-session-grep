//! Private after-exit cleanup. Plans grant no wildcard/path or process authority.
//! The native parent retains one noninheritable OS lock until process exit; the
//! child must acquire that SAME inode before changing any planned payload file.
use super::*;
use agent_session_grep_adapters_sqlite::{
    control::{INSTALLATION_LOCK_KEY, SealedControlFile},
    managed_locks::JobLockKey,
    managed_purge::PrivateArtifactClass,
};
use agent_session_grep_ports::control::{ControlSeq, PolicyEpoch};
use std::io::Write;

#[path = "managed_reinstall_handoff.rs"]
mod managed_reinstall_handoff;

const CHILD: &str = "__managed-uninstall-cleanup";
pub(super) const WINDOWS_TAIL_HELPER: &str = "package-uninstall.ps1";
const PLAN_SCHEMA: &str = "asg.uninstall-helper/v1";
const SEAL_SCHEMA: &str = "asg.uninstall-seal/v1";
const MAX_PLAN: u64 = 4 * 1024 * 1024;
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const INSTALLATION_LOCK: &str = "maintenance-job-696e7374616c6c6174696f6e2d757064617465.lock";
const DATA_LOCKS: &[&str] = &[
    "policy-owner.lock",
    "policy-emission.lock",
    "control-create.lock",
    "catalog-handles.lock",
    "history-readers.lock",
    "background.lock",
    "supervisor.lock",
    "maintenance-job-6f776e65642d7075726765.lock",
];
const EMPTY_RENDEZVOUS: &[&str] = &[
    "policy-owner.lock",
    "policy-emission.lock",
    "control-create.lock",
    "catalog-handles.lock",
    "control-handles.lock",
    "history-readers.lock",
    "background.lock",
    "supervisor.lock",
    "maintenance-job-6f776e65642d7075726765.lock",
    "maintenance-job-757365722d70617468.lock",
    "maintenance-job-6c65676163792d6d6967726174696f6e.lock",
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HelperPlan {
    schema: String,
    nonce: String,
    pub(super) runner: OwnedFile,
    parent_exit: OwnedFile,
    runner_exit: OwnedFile,
    manifest: OwnedFile,
    seal: OwnedFile,
    tail: Option<OwnedFile>,
    #[serde(default)]
    installation_lock: Option<OwnedFile>,
    #[serde(default)]
    data_locks: Vec<OwnedFile>,
    #[serde(default)]
    retirement_marker: Option<OwnedFile>,
    #[serde(default)]
    retained_data: Vec<OwnedFile>,
    #[serde(default)]
    deadline_tick: Option<u64>,
    #[serde(default)]
    payload_complete: bool,
    #[serde(default)]
    tail_pending: bool,
    #[serde(default)]
    tail_handoff_sequence: Option<u64>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateMetadata {
    pub(super) removable: Vec<OwnedFile>,
    pub(super) preserved: Vec<OwnedFile>,
    #[serde(default)]
    pub(super) retained: Vec<OwnedFile>,
    pub(super) classified: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TailResult {
    schema: String,
    nonce: String,
    seal_sha256: String,
    receipt_sequence: u64,
    receipt_sha256: String,
    deadline_tick: u64,
    tail_removed: bool,
    runner_removed: bool,
    complete: bool,
    reason: String,
}
/// Classification of the recorded acknowledgement, not proof that current
/// owners have drained or that reinstall may activate a new lifecycle.
#[derive(Debug, PartialEq, Eq)]
enum TailReceiptCompletion {
    Complete,
    Pending,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootPins {
    prefix: (u64, u64),
    data: (u64, u64),
    journal: (u64, u64),
    helper: (u64, u64),
}
impl RootPins {
    fn capture(journal: &Journal) -> Result<Self, Reason> {
        let identity = |path: &Path| {
            platform::identity(&platform::directory(path).map_err(|_| Reason::IdentityChanged)?)
                .map_err(|_| Reason::IdentityChanged)
        };
        Ok(Self {
            prefix: identity(&journal.prefix)?,
            data: identity(journal.catalog.parent().ok_or(Reason::IdentityChanged)?)?,
            journal: identity(&journal.root)?,
            helper: identity(&journal.root.join("helper"))?,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    schema: String,
    owner: Owner,
    roots: RootPins,
    owner_file: OwnedFile,
    catalog_incarnation: String,
    policy: TerminalPolicy,
    package_manifest_sha256: String,
    package_files: Vec<OwnedFile>,
    metadata: PrivateMetadata,
    runner: OwnedFile,
    parent_exit: OwnedFile,
    runner_exit: OwnedFile,
    manifest: OwnedFile,
    tail: Option<OwnedFile>,
    tail_source: Option<OwnedFile>,
}
impl HelperPlan {
    pub(super) fn validate(&self, state: &DeferredCleanup) -> Result<(), Reason> {
        if self.schema != PLAN_SCHEMA
            || self.nonce != state.owner.nonce
            || self.runner.relative
                != if cfg!(windows) {
                    "helper/runner.exe"
                } else {
                    "helper/runner"
                }
            || self.parent_exit.relative != "helper/parent-exit.lock"
            || self.runner_exit.relative != "helper/runner-exit.lock"
            || self.manifest.relative != "helper/PACKAGE-MANIFEST.tsv"
            || self.seal.relative != "helper/seal.json"
            || self
                .tail
                .as_ref()
                .is_some_and(|file| file.relative != "helper/tail.ps1")
            || [&self.parent_exit, &self.runner_exit]
                .iter()
                .any(|file| file.size != 0 || file.digest != EMPTY_SHA)
        {
            return Err(Reason::IdentityChanged);
        }
        for proof in [
            &self.runner,
            &self.parent_exit,
            &self.runner_exit,
            &self.manifest,
            &self.seal,
        ]
        .into_iter()
        .chain(self.tail.iter())
        {
            if !package_installation::safe_member(&proof.relative)
                || !package_installation::hex(&proof.digest, 64)
                || proof.size > MAX_FILE
            {
                return Err(Reason::IdentityChanged);
            }
        }
        if self.installation_lock.as_ref().is_some_and(|file| {
            file.relative != INSTALLATION_LOCK || file.size != 0 || file.digest != EMPTY_SHA
        }) || self.data_locks.iter().any(|file| {
            !DATA_LOCKS.contains(&file.relative.as_str())
                || file.size != 0
                || file.digest != EMPTY_SHA
        }) || self
            .retirement_marker
            .as_ref()
            .is_some_and(|file| file.relative != RETIREMENT_MARKER)
        {
            return Err(Reason::IdentityChanged);
        }
        Ok(())
    }
}

/// Only typed integration records are included. Preserved user setting images
/// keep their complete journal/locator chain; familiar names alone grant nothing.
pub(super) fn classify_private(
    install: &Installation,
    control: &SqliteControlStore,
    journal: &Journal,
    end: Instant,
) -> Result<PrivateMetadata, Reason> {
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    let inventory =
        crate::managed_purge::artifact_inventory(control, &journal.catalog, Some(install), end)
            .map_err(|_| Reason::PrivateMetadataCleanupPending)?;
    let policy = journal.validate(control, end)?;
    let mut metadata = PrivateMetadata {
        classified: true,
        ..Default::default()
    };
    for (class, relative, size, blake3_digest) in inventory.artifacts() {
        time(end)?;
        let bytes = update_state::read(&root.join(relative), MAX_PLAN)
            .map_err(|_| Reason::PrivateMetadataCleanupPending)?
            .ok_or(Reason::FileChanged)?;
        if bytes.len() as u64 != size || blake3::hash(&bytes).to_hex().as_str() != blake3_digest {
            return Err(Reason::FileChanged);
        }
        let proof = owned_file(root, relative, &policy, end)?;
        match class {
            PrivateArtifactClass::SetupInventory
            | PrivateArtifactClass::NativeRegistration
            | PrivateArtifactClass::UserPathRegistration => metadata.preserved.push(proof),
            PrivateArtifactClass::CatalogRestoreReceipt if journal.state.owner.keep_data => {
                // Retained catalog/backups keep their verified recovery lineage.
                metadata.retained.push(proof)
            }
            PrivateArtifactClass::LegacyMigrationIntent
            | PrivateArtifactClass::UpdateJournal
            | PrivateArtifactClass::CatalogRestoreReceipt => metadata.removable.push(proof),
        }
    }
    // These immutable empty rendezvous leaves have been admitted by the live
    // control root. They are retained, never granted deletion by their names.
    for name in EMPTY_RENDEZVOUS {
        if fs::symlink_metadata(root.join(name)).is_ok() {
            let proof = owned_file(root, name, &policy, end)?;
            if proof.size != 0 || proof.digest != EMPTY_SHA {
                return Err(Reason::UnclassifiedOwnedArtifact);
            }
            metadata.retained.push(proof);
        }
    }
    let marker_name = format!("{}.asg-managed-create", journal.state.owner.catalog_name);
    if fs::symlink_metadata(root.join(&marker_name)).is_ok() {
        // The live catalog incarnation/physical file was captured before this
        // fence (and default RetirementIntent::bind independently checks it).
        // Do not reopen the normal facade under Uninstalling.
        if platform::identity(
            &platform::open_file(&journal.catalog).map_err(|_| Reason::CorpusCleanupPending)?,
        )
        .map_err(|_| Reason::IdentityChanged)?
            != journal.state.catalog_file_identity
        {
            return Err(Reason::IdentityChanged);
        }
        let marker = owned_file(root, &marker_name, &policy, end)?;
        if marker.size != 0 || marker.digest != EMPTY_SHA {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
        if journal.state.owner.keep_data {
            metadata.retained.push(marker);
        } else {
            metadata.removable.push(marker);
        }
    }
    let association = owned_file(root, "installation-prefix.json", &policy, end)?;
    if journal.state.owner.keep_data {
        metadata.retained.push(association);
        for record in control
            .backup_records()
            .map_err(|_| Reason::BackupCleanupPending)?
        {
            if record.state == BackupState::PurgedByPolicy {
                continue;
            }
            if record.state != BackupState::Complete {
                return Err(Reason::BackupCleanupPending);
            }
            let verified = verify_backup_until(control, &record.backup_id, end)
                .map_err(|_| Reason::BackupCleanupPending)?;
            let proof = owned_file(root, &record.relative_locator, &policy, end)?;
            if proof.digest != verified.metadata().digest
                || proof.size != verified.metadata().size_bytes
            {
                return Err(Reason::FileChanged);
            }
            let sidecar = Path::new(&record.relative_locator)
                .parent()
                .ok_or(Reason::IdentityChanged)?
                .join("manifest.json");
            metadata.retained.push(proof);
            metadata.retained.push(owned_file(
                root,
                sidecar.to_str().ok_or(Reason::IdentityChanged)?,
                &policy,
                end,
            )?);
        }
    } else {
        metadata.removable.push(association);
    }
    Ok(metadata)
}

/// Capture one immutable native runner plus manifest-verified optional Windows
/// tail. The complete seal is durable BEFORE scheduling or deleting payloads.
pub(super) fn prepare(
    install: &Installation,
    journal: &mut Journal,
    end: Instant,
) -> Result<(), Reason> {
    journal.validate_roots(end)?;
    require_completed_path(journal)?;
    if journal.state.after_exit.is_some() {
        return Ok(());
    }
    let policy = journal
        .state
        .terminal_policy
        .clone()
        .ok_or(Reason::AfterExitCleanupPending)?;
    let helper = journal.root.join("helper");
    platform::create_private_directory(&helper).map_err(|_| Reason::AfterExitCleanupPending)?;
    checked_root(&helper).map_err(|_| Reason::IdentityChanged)?;
    if fs::read_dir(&helper)
        .map_err(|_| Reason::AfterExitCleanupPending)?
        .next()
        .is_some()
    {
        return Err(Reason::AfterExitCleanupPending);
    }
    let app_relative = format!("{}/{}", install.pointer.dir, install.pointer.app);
    let application = journal
        .state
        .package_files
        .iter()
        .find(|file| file.relative == app_relative)
        .filter(|file| file.digest == install.pointer.app_sha256)
        .ok_or(Reason::IdentityChanged)?;
    copy_verified(
        &install.prefix,
        application,
        &journal.root,
        if cfg!(windows) {
            "helper/runner.exe"
        } else {
            "helper/runner"
        },
        &policy,
        true,
        end,
    )?;
    copy_verified(
        &install.prefix,
        journal
            .state
            .package_files
            .iter()
            .find(|file| file.relative == "PACKAGE-MANIFEST.tsv")
            .ok_or(Reason::IdentityChanged)?,
        &journal.root,
        "helper/PACKAGE-MANIFEST.tsv",
        &policy,
        false,
        end,
    )?;
    let tail = if cfg!(windows) {
        match install.helpers.get(super::WINDOWS_TAIL_HELPER) {
            Some(verified) => {
                let expected = install
                    .prefix
                    .join(&install.pointer.dir)
                    .join("helpers")
                    .join(WINDOWS_TAIL_HELPER);
                if verified.path != expected {
                    return Err(Reason::IdentityChanged);
                }
                let relative = expected
                    .strip_prefix(&install.prefix)
                    .map_err(|_| Reason::IdentityChanged)?
                    .to_str()
                    .ok_or(Reason::IdentityChanged)?
                    .replace('\\', "/");
                let proof = journal
                    .state
                    .package_files
                    .iter()
                    .find(|file| file.relative == relative)
                    .filter(|file| file.digest == verified.sha256)
                    .ok_or(Reason::IdentityChanged)?;
                copy_verified(
                    &install.prefix,
                    proof,
                    &journal.root,
                    "helper/tail.ps1",
                    &policy,
                    false,
                    end,
                )?;
                copy_verified(
                    &install.prefix,
                    proof,
                    &journal.root,
                    "helper/tail-source.ps1",
                    &policy,
                    false,
                    end,
                )?;
                Some(private_proof(
                    &journal.root,
                    "helper/tail.ps1",
                    &policy,
                    end,
                )?)
            }
            None => None, // Historical packages have no retroactive helper authority.
        }
    } else {
        None
    };
    for relative in ["helper/parent-exit.lock", "helper/runner-exit.lock"] {
        update_state::write_new(&journal.root.join(relative), b"")
            .map_err(|_| Reason::AfterExitCleanupPending)?;
    }
    let runner = private_proof(
        &journal.root,
        if cfg!(windows) {
            "helper/runner.exe"
        } else {
            "helper/runner"
        },
        &policy,
        end,
    )?;
    let parent_exit = private_proof(&journal.root, "helper/parent-exit.lock", &policy, end)?;
    let runner_exit = private_proof(&journal.root, "helper/runner-exit.lock", &policy, end)?;
    let manifest = private_proof(&journal.root, "helper/PACKAGE-MANIFEST.tsv", &policy, end)?;
    if manifest.digest != journal.state.package_manifest_sha256 {
        return Err(Reason::FileChanged);
    }
    let seal_value = Seal {
        schema: SEAL_SCHEMA.into(),
        owner: journal.state.owner.clone(),
        roots: RootPins::capture(journal)?,
        owner_file: private_proof(&journal.root, "owner.json", &policy, end)?,
        catalog_incarnation: journal.state.catalog_incarnation.clone(),
        policy: policy.clone(),
        package_manifest_sha256: journal.state.package_manifest_sha256.clone(),
        package_files: journal.state.package_files.clone(),
        metadata: journal.state.private_metadata.clone(),
        runner: runner.clone(),
        parent_exit: parent_exit.clone(),
        runner_exit: runner_exit.clone(),
        manifest: manifest.clone(),
        tail: tail.clone(),
        tail_source: if tail.is_some() {
            Some(private_proof(
                &journal.root,
                "helper/tail-source.ps1",
                &policy,
                end,
            )?)
        } else {
            None
        },
    };
    let bytes = serde_json::to_vec(&seal_value).map_err(|_| Reason::AfterExitCleanupPending)?;
    if bytes.len() as u64 > MAX_PLAN {
        return Err(Reason::AfterExitCleanupPending);
    }
    update_state::write_new(&helper.join("seal.json"), &bytes)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    let seal = private_proof(&journal.root, "helper/seal.json", &policy, end)?;
    journal.state.after_exit = Some(HelperPlan {
        schema: PLAN_SCHEMA.into(),
        nonce: journal.state.owner.nonce.clone(),
        runner,
        parent_exit,
        runner_exit,
        manifest,
        seal,
        tail,
        installation_lock: None,
        data_locks: Vec::new(),
        retirement_marker: None,
        retained_data: Vec::new(),
        deadline_tick: None,
        payload_complete: false,
        tail_pending: false,
        tail_handoff_sequence: None,
    });
    journal.state.report.recovery_entry_recorded = true;
    journal
        .save(end)
        .map_err(|_| Reason::AfterExitCleanupPending)
}
fn private_proof(
    base: &Path,
    relative: &str,
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<OwnedFile, Reason> {
    owned_file_with_overlap(base, relative, &|path| policy.overlaps(path), end)
}
fn verify(
    base: &Path,
    proof: &OwnedFile,
    policy: &TerminalPolicy,
    end: Instant,
    absent: bool,
) -> Result<bool, Reason> {
    time(end)?;
    match fs::symlink_metadata(base.join(&proof.relative)) {
        Err(error) if absent && error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Reason::FileLocked),
        Ok(_) => {}
    }
    let current = private_proof(base, &proof.relative, policy, end)?;
    if current.identity != proof.identity
        || current.digest != proof.digest
        || current.size != proof.size
    {
        return Err(Reason::FileChanged);
    }
    if !fs::canonicalize(base.join(&proof.relative))
        .map_err(|_| Reason::IdentityChanged)?
        .starts_with(fs::canonicalize(base).map_err(|_| Reason::IdentityChanged)?)
    {
        return Err(Reason::IdentityChanged);
    }
    Ok(true)
}
fn copy_verified(
    source_root: &Path,
    proof: &OwnedFile,
    destination: &Path,
    relative: &str,
    policy: &TerminalPolicy,
    executable: bool,
    end: Instant,
) -> Result<(), Reason> {
    verify(source_root, proof, policy, end, false)?;
    let mut input = package_installation::pinned(&source_root.join(&proof.relative))
        .map_err(|_| Reason::FileLocked)?;
    let mut output = platform::create_file(&destination.join(relative))
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    let mut buffer = [0; 65536];
    loop {
        time(end)?;
        let count = input.read(&mut buffer).map_err(|_| Reason::FileLocked)?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|_| Reason::AfterExitCleanupPending)?;
    }
    output
        .sync_all()
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(fs::Permissions::from_mode(if executable {
                0o700
            } else {
                0o600
            }))
            .map_err(|_| Reason::AfterExitCleanupPending)?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    drop(output);
    if private_proof(destination, relative, policy, end)?.digest != proof.digest {
        return Err(Reason::FileChanged);
    }
    verify(source_root, proof, policy, end, false)?;
    platform::sync_directory(
        destination
            .join(relative)
            .parent()
            .ok_or(Reason::IdentityChanged)?,
    )
    .map_err(|_| Reason::AfterExitCleanupPending)
}
fn open_journal(prefix: &Path, catalog: &Path, end: Instant) -> Result<Journal, CliError> {
    let state = read_deferred_cleanup(prefix, catalog, end)?
        .ok_or_else(|| error(CanonicalCode::SchemaIncompatible))?;
    let root = prefix.join("uninstall");
    let mut journal = Journal {
        prefix: prefix.into(),
        catalog: catalog.into(),
        prefix_identity: RootIdentity::read(prefix).map_err(port)?,
        data_identity: checked_root(
            catalog
                .parent()
                .ok_or_else(|| error(CanonicalCode::InvalidRequest))?,
        )?,
        _directory: platform::directory(&root).map_err(|_| error(CanonicalCode::SourceIo))?,
        root,
        state,
        receipt_digest: None,
    };
    journal.capture_receipt()?;
    journal
        .validate_roots(end)
        .map_err(|_| error(CanonicalCode::SourceChanged))?;
    Ok(journal)
}
fn read_seal(journal: &Journal, end: Instant) -> Result<Seal, Reason> {
    journal.validate_roots(end)?;
    let plan = journal
        .state
        .after_exit
        .as_ref()
        .ok_or(Reason::AfterExitCleanupPending)?;
    plan.validate(&journal.state)?;
    let policy = journal
        .state
        .terminal_policy
        .as_ref()
        .ok_or(Reason::IdentityChanged)?;
    verify(&journal.root, &plan.seal, policy, end, false)?;
    verify(&journal.root, &plan.manifest, policy, end, false)?;
    let bytes = update_state::read(&journal.root.join(&plan.seal.relative), MAX_PLAN)
        .map_err(|_| Reason::IdentityChanged)?
        .ok_or(Reason::IdentityChanged)?;
    let manifest_bytes =
        update_state::read(&journal.root.join(&plan.manifest.relative), INVENTORY_LIMIT)
            .map_err(|_| Reason::IdentityChanged)?
            .ok_or(Reason::IdentityChanged)?;
    let seal = decode_seal(
        &journal.state,
        RootPins::capture(journal)?,
        &bytes,
        &manifest_bytes,
    )?;
    verify(&journal.root, &seal.owner_file, policy, end, false)?;
    Ok(seal)
}

/// Common semantics for active and intent-bound record readers. Physical
/// identity, exact bytes and live guards remain the reader's responsibility.
fn decode_seal(
    state: &DeferredCleanup,
    roots: RootPins,
    bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<Seal, Reason> {
    let plan = state.after_exit.as_ref().ok_or(Reason::IdentityChanged)?;
    plan.validate(state)?;
    let policy = state
        .terminal_policy
        .as_ref()
        .ok_or(Reason::IdentityChanged)?;
    let seal: Seal = serde_json::from_slice(bytes).map_err(|_| Reason::IdentityChanged)?;
    if seal.schema != SEAL_SCHEMA
        || seal.owner != state.owner
        || seal.roots != roots
        || seal.catalog_incarnation != state.catalog_incarnation
        || seal.package_manifest_sha256 != state.package_manifest_sha256
        || serde_json::to_vec(&seal.package_files).ok()
            != serde_json::to_vec(&state.package_files).ok()
        || seal.runner.identity != plan.runner.identity
        || seal.runner.digest != plan.runner.digest
        || seal.parent_exit.identity != plan.parent_exit.identity
        || seal.runner_exit.identity != plan.runner_exit.identity
    {
        return Err(Reason::IdentityChanged);
    }
    seal.policy.validate()?;
    if serde_json::to_vec(&seal.policy).ok() != serde_json::to_vec(policy).ok()
        || serde_json::to_vec(&seal.metadata).ok()
            != serde_json::to_vec(&state.private_metadata).ok()
    {
        return Err(Reason::IdentityChanged);
    }
    let manifest = Manifest::parse(manifest_bytes).map_err(|_| Reason::IdentityChanged)?;
    let app = format!(
        "{}/{}",
        manifest.field("dir").map_err(|_| Reason::IdentityChanged)?,
        manifest.field("app").map_err(|_| Reason::IdentityChanged)?
    );
    if !manifest
        .members
        .get(&app)
        .is_some_and(|member| member.sha == seal.runner.digest && member.size == seal.runner.size)
    {
        return Err(Reason::IdentityChanged);
    }
    validate_manifest_plan(&manifest, &seal)?;
    Ok(seal)
}
fn validate_manifest_plan(manifest: &Manifest, seal: &Seal) -> Result<(), Reason> {
    let mut names = BTreeSet::new();
    for proof in &seal.package_files {
        if !names.insert(proof.relative.as_str()) {
            return Err(Reason::IdentityChanged);
        }
        if let Some(member) = manifest.members.get(&proof.relative) {
            if member.sha != proof.digest || member.size != proof.size {
                return Err(Reason::FileChanged);
            }
        } else if !matches!(
            proof.relative.as_str(),
            "PACKAGE-MANIFEST.tsv"
                | "package-install.json"
                | "release.manifest.json"
                | "SHA256SUMS"
        ) {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
    }
    if manifest
        .members
        .keys()
        .any(|name| !names.contains(name.as_str()))
        || !names.contains("PACKAGE-MANIFEST.tsv")
        || !names.contains("package-install.json")
    {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    match (&seal.tail, &seal.tail_source) {
        (Some(tail), Some(source)) => {
            let member = format!(
                "{}/helpers/{}",
                manifest.field("dir").map_err(|_| Reason::IdentityChanged)?,
                WINDOWS_TAIL_HELPER
            );
            if source.relative != "helper/tail-source.ps1"
                || source.digest != tail.digest
                || source.size != tail.size
                || !manifest
                    .members
                    .get(&member)
                    .is_some_and(|m| m.sha == tail.digest && m.size == tail.size)
            {
                return Err(Reason::IdentityChanged);
            }
        }
        (None, None) => {}
        _ => return Err(Reason::IdentityChanged),
    }
    Ok(())
}

/// Called only by the real public command after a durable terminal plan exists.
/// The leaked handle is deliberate: releasing it on function return would falsely
/// tell a helper that the executing app (and its launcher) had already exited.
pub(super) fn schedule(
    db: &str,
    prefix: Option<PathBuf>,
    end: Instant,
) -> Result<Report, CliError> {
    let prefix = match prefix {
        Some(prefix) => prefix,
        None => package_installation::installation(None)?.prefix,
    };
    let catalog = package_installation::absolute(Path::new(db))?;
    let mut journal = open_journal(&prefix, &catalog, end)?;
    let lock = update_state::acquire_installation_lock(&prefix, end)?;
    if !journal.state.report.path_cleanup_complete()
        || journal
            .state
            .report
            .reasons
            .contains(&Reason::PathConfigurationRetained)
    {
        journal
            .state
            .report
            .pending(Reason::PathConfigurationRetained);
        journal.save_before_deadline(end)?;
        return Ok(journal.state.report);
    }
    let result = (|| -> Result<(), Reason> {
        let seal = read_seal(&journal, end)?;
        let mut plan = journal
            .state
            .after_exit
            .clone()
            .ok_or(Reason::AfterExitCleanupPending)?;
        verify(&journal.root, &plan.runner, &seal.policy, end, false)?;
        let parent = exit_lock(&journal.root, &plan.parent_exit, &seal.policy, end, false)?;
        plan.deadline_tick = Some(deadline_tick(end)?);
        journal.state.after_exit = Some(plan.clone());
        journal.state.report.after_exit_cleanup_pending = true;
        journal
            .state
            .report
            .pending(Reason::AfterExitCleanupPending);
        journal
            .save(end)
            .map_err(|_| Reason::AfterExitCleanupPending)?;
        let args = [
            OsString::from(CHILD),
            OsString::from("--prefix"),
            prefix.as_os_str().into(),
            OsString::from("--catalog"),
            catalog.as_os_str().into(),
            OsString::from("--nonce"),
            plan.nonce.into(),
            OsString::from("--deadline-tick"),
            plan.deadline_tick
                .ok_or(Reason::Deadline)?
                .to_string()
                .into(),
        ];
        let child = agent_session_grep_launcher::spawn_verified_background(
            &journal.root.join(&plan.runner.relative),
            &plan.runner.digest,
            &args,
        )
        .map_err(|_| Reason::AfterExitCleanupPending)?;
        std::mem::forget(parent); // noninheritable; OS closes only when this process exits.
        drop(child);
        Ok(())
    })();
    drop(lock);
    if let Err(reason) = result {
        journal.state.report.pending(reason);
    }
    journal.save_before_deadline(end)?;
    Ok(journal.state.report)
}
/// Only `exit_lock` constructs this after acquiring the verified inode. Do not
/// expose the file or implement Deref/Clone: callers must not unlock a borrowed
/// exit capability or keep a duplicate alive after this guard is dropped.
struct ExitGuard {
    file: File,
    root: RootIdentity,
    relative: String,
}

impl ExitGuard {
    fn validate_current(
        &self,
        base: &Path,
        proof: &OwnedFile,
        policy: &TerminalPolicy,
        end: Instant,
    ) -> Result<(), Reason> {
        time(end)?;
        if self.relative != proof.relative
            || proof.size != 0
            || proof.digest != EMPTY_SHA
            || RootIdentity::read(base).map_err(|_| Reason::IdentityChanged)? != self.root
        {
            return Err(Reason::IdentityChanged);
        }
        let metadata = self.file.metadata().map_err(|_| Reason::FileChanged)?;
        if !metadata.is_file()
            || metadata.len() != 0
            || platform::identity(&self.file).map_err(|_| Reason::FileChanged)? != proof.identity
        {
            return Err(Reason::FileChanged);
        }
        // Verify the named empty file without reading bytes through another
        // handle to a Windows mandatory lock. This also rejects linked aliases.
        let path = base.join(&proof.relative);
        package_installation::ordinary(&path).map_err(|_| Reason::IdentityChanged)?;
        let current = platform::open_file(&path).map_err(|_| Reason::FileChanged)?;
        if current.metadata().map_err(|_| Reason::FileChanged)?.len() != 0
            || platform::identity(&current).map_err(|_| Reason::FileChanged)? != proof.identity
        {
            return Err(Reason::FileChanged);
        }
        verify(base, proof, policy, end, false)?;
        if RootIdentity::read(base).map_err(|_| Reason::IdentityChanged)? != self.root {
            return Err(Reason::IdentityChanged);
        }
        time(end)
    }
}

fn exit_lock(
    base: &Path,
    proof: &OwnedFile,
    policy: &TerminalPolicy,
    end: Instant,
    wait: bool,
) -> Result<ExitGuard, Reason> {
    if proof.size != 0 || proof.digest != EMPTY_SHA {
        return Err(Reason::IdentityChanged);
    }
    let path = base.join(&proof.relative);
    loop {
        time(end)?;
        package_installation::ordinary(&path).map_err(|_| Reason::IdentityChanged)?;
        if policy.overlaps(&path)? {
            return Err(Reason::SourceOverlap);
        }
        let root = RootIdentity::read(base).map_err(|_| Reason::IdentityChanged)?;
        let file = platform::open_file(&path).map_err(|_| Reason::FileLocked)?;
        // Query metadata before acquisition; reading a byte through another
        // handle to an exclusive Windows lock would fail instead of waiting.
        if file.metadata().map_err(|_| Reason::FileChanged)?.len() != 0
            || platform::identity(&file).map_err(|_| Reason::FileChanged)? != proof.identity
        {
            return Err(Reason::FileChanged);
        }
        match file.try_lock() {
            Ok(()) => {
                let guard = ExitGuard {
                    file,
                    root,
                    relative: proof.relative.clone(),
                };
                guard.validate_current(base, proof, policy, end)?;
                return Ok(guard);
            }
            Err(fs::TryLockError::WouldBlock) if wait => {
                #[cfg(test)]
                observe_cleanup_admission(CleanupAdmissionEvent::ExitWouldBlock(path.clone()), end);
                std::thread::sleep(
                    Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
                );
            }
            Err(_) => return Err(Reason::AfterExitCleanupPending),
        }
    }
}
/// No stderr/stdout, subprocess exit/PID query or ambient installation fallback.
/// --recover is accepted only when executing the exact sealed private runner.
pub(super) fn intercept(args: &[OsString]) -> Option<i32> {
    if let Some(result) = managed_reinstall_handoff::intercept(args) {
        return Some(result);
    }
    if args.first().is_none_or(|arg| arg != CHILD) {
        return None;
    }
    let parsed = (|| -> Result<_, Reason> {
        match args {
            [_, p, prefix, c, catalog, n, nonce, d, tick]
                if p == "--prefix"
                    && c == "--catalog"
                    && n == "--nonce"
                    && d == "--deadline-tick" =>
            {
                let tick = tick
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or(Reason::Deadline)?;
                Ok((
                    PathBuf::from(prefix),
                    PathBuf::from(catalog),
                    nonce.to_str().ok_or(Reason::IdentityChanged)?.to_owned(),
                    tick,
                    false,
                ))
            }
            [_, p, prefix, c, catalog, n, nonce, recover]
                if p == "--prefix"
                    && c == "--catalog"
                    && n == "--nonce"
                    && recover == "--recover" =>
            {
                Ok((
                    PathBuf::from(prefix),
                    PathBuf::from(catalog),
                    nonce.to_str().ok_or(Reason::IdentityChanged)?.to_owned(),
                    deadline_tick(Instant::now() + BUDGET)?,
                    true,
                ))
            }
            _ => Err(Reason::IdentityChanged),
        }
    })();
    Some(match parsed {
        Ok((prefix, catalog, nonce, tick, recover)) => {
            if run_child(&prefix, &catalog, &nonce, tick, recover).is_ok() {
                0
            } else {
                10
            }
        }
        Err(_) => 2,
    })
}
fn run_child(
    prefix: &Path,
    catalog: &Path,
    nonce: &str,
    tick: u64,
    recover: bool,
) -> Result<(), Reason> {
    let end = end_from_tick(tick)?;
    let mut journal = open_journal(prefix, catalog, end).map_err(|_| Reason::IdentityChanged)?;
    let seal = read_seal(&journal, end)?;
    let mut plan = journal
        .state
        .after_exit
        .clone()
        .ok_or(Reason::AfterExitCleanupPending)?;
    if plan.nonce != nonce || (!recover && plan.deadline_tick != Some(tick)) {
        return Err(Reason::IdentityChanged);
    }
    #[cfg(test)]
    observe_cleanup_admission(CleanupAdmissionEvent::BeforeImage, end);
    let running = std::env::current_exe().map_err(|_| Reason::IdentityChanged)?;
    if fs::canonicalize(&running).map_err(|_| Reason::IdentityChanged)?
        != fs::canonicalize(journal.root.join(&plan.runner.relative))
            .map_err(|_| Reason::IdentityChanged)?
    {
        return Err(Reason::IdentityChanged);
    }
    verify(&journal.root, &plan.runner, &seal.policy, end, false)?;
    let parent_exited = exit_lock(&journal.root, &plan.parent_exit, &seal.policy, end, true)?;
    let runner_owner = exit_lock(&journal.root, &plan.runner_exit, &seal.policy, end, false)?;
    let installation = update_state::acquire_installation_lock(prefix, end)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    validate_installation_guard(&journal, &installation, end)?;
    require_completed_path(&journal)?;
    if recover {
        plan.deadline_tick = Some(tick);
        journal.state.after_exit = Some(plan);
    }
    let result = if consume_tail_result(&mut journal, &seal, end)? {
        Ok(())
    } else {
        finalize(
            &mut journal,
            &seal,
            &installation,
            &parent_exited,
            &runner_owner,
            end,
        )
    };
    match &result {
        Err(reason)
            if journal.state.report.cleanup_pending
                || journal.state.report.after_exit_cleanup_pending =>
        {
            journal.state.report.pending(*reason);
            journal
                .save_before_deadline(end)
                .map_err(|_| Reason::AfterExitCleanupPending)?;
        }
        Ok(()) if cfg!(windows) => {
            // launch_tail already flushed its exact handoff receipt. Writing another
            // would sever the tail's sequence/digest binding to that durable intent.
            std::mem::forget(runner_owner);
        }
        // Unix completion is the last acknowledged write in finalize. No
        // fallible receipt save or validation may turn that commit into failure.
        // Rechecking an older completed receipt also never rewrites that receipt.
        Err(_) | Ok(()) => {}
    }
    result
}
fn validate_installation_guard(
    journal: &Journal,
    installation: &ExclusiveGuard,
    end: Instant,
) -> Result<(), Reason> {
    journal.validate_roots(end)?;
    let kind = LockKind::MaintenanceJob(
        JobLockKey::parse(INSTALLATION_LOCK_KEY).map_err(|_| Reason::IdentityChanged)?,
    );
    if installation.kind() != &kind || installation.root_identity() != journal.prefix_identity {
        return Err(Reason::IdentityChanged);
    }
    installation
        .validate_current(&journal.prefix)
        .map_err(|_| Reason::IdentityChanged)?;
    time(end)
}

/// Views of the actual held guards, split at the writer field so an existing
/// retirement can keep borrowing the other drains while diagnostics are read.
struct CompletionGuards<'a> {
    parent_exit: &'a ExitGuard,
    runner_exit: &'a ExitGuard,
    prefix: &'a ExclusiveGuard,
    drains: RetirementDrainGuards<'a>,
    writer: &'a mut WriterLease,
    history: &'a ExclusiveGuard,
}

enum CompletionMode<'a, 'held> {
    KeepData {
        control: &'a SqliteControlStore,
        installation: &'a InstallationLockAuthority<'held>,
    },
    Default {
        retirement: &'a ControlRetirement<'held>,
    },
}

#[derive(PartialEq, Eq)]
struct CompletionFile {
    identity: (u64, u64),
    size: u64,
    // SQLite owns transient WAL-index bookkeeping. Its ordinary/private name
    // is checked, but its bytes are not a durable completion preimage.
    sha256: Option<String>,
}

#[derive(PartialEq, Eq)]
struct CompletionEvidence {
    roots: RootPins,
    sequence: u64,
    tail_sequence: Option<u64>,
    files: BTreeMap<String, Option<CompletionFile>>,
}

#[derive(Clone, Copy)]
enum CompletionReceiptCheck {
    Published,
    BeforePublication,
}

/// Private point-in-time completion proof. It keeps the real guards, mode and
/// journal borrowed; subsequent effects still have to revalidate its evidence.
#[must_use = "completion evidence is valid only while the actual guards remain borrowed"]
struct CompletedUninstall<'a, 'guards, 'mode, 'held> {
    journal: &'a Journal,
    guards: &'a mut CompletionGuards<'guards>,
    mode: &'a CompletionMode<'mode, 'held>,
    end: Instant,
    evidence: CompletionEvidence,
}

impl CompletedUninstall<'_, '_, '_, '_> {
    fn validate_current(&mut self) -> Result<(), Reason> {
        let end = SqliteControlStore::effective_runtime_deadline(self.end);
        let current = completion_with_deadline(self.mode, end, || {
            completion_pass(
                self.journal,
                self.guards,
                self.mode,
                CompletionReceiptCheck::Published,
                end,
            )
        })?;
        if current != self.evidence {
            return Err(Reason::IdentityChanged);
        }
        time(end)
    }
}

fn inspect_completed_uninstall<'a, 'guards, 'mode, 'held>(
    journal: &'a Journal,
    guards: &'a mut CompletionGuards<'guards>,
    mode: &'a CompletionMode<'mode, 'held>,
    end: Instant,
) -> Result<CompletedUninstall<'a, 'guards, 'mode, 'held>, Reason> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    time(end)?;
    let evidence = completion_with_deadline(mode, end, || {
        let evidence = completion_pass(
            journal,
            guards,
            mode,
            CompletionReceiptCheck::Published,
            end,
        )?;
        #[cfg(test)]
        tests::between_completion_passes();
        if completion_pass(
            journal,
            guards,
            mode,
            CompletionReceiptCheck::Published,
            end,
        )? != evidence
        {
            return Err(Reason::IdentityChanged);
        }
        Ok(evidence)
    })?;
    time(end)?;
    Ok(CompletedUninstall {
        journal,
        guards,
        mode,
        end,
        evidence,
    })
}

/// Read the still-pending receipt and all physical evidence before publication.
/// This grants no completed-receipt proof and changes no journal/report bytes.
fn preflight_uninstall_completion(
    journal: &Journal,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
) -> Result<(), Reason> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    completion_with_deadline(mode, end, || {
        let evidence = completion_pass(
            journal,
            guards,
            mode,
            CompletionReceiptCheck::BeforePublication,
            end,
        )?;
        #[cfg(test)]
        tests::between_completion_passes();
        if completion_pass(
            journal,
            guards,
            mode,
            CompletionReceiptCheck::BeforePublication,
            end,
        )? != evidence
        {
            return Err(Reason::IdentityChanged);
        }
        time(end)
    })
}

fn completion_with_deadline<T>(
    mode: &CompletionMode<'_, '_>,
    end: Instant,
    inspect: impl FnOnce() -> Result<T, Reason>,
) -> Result<T, Reason> {
    time(end)?;
    let result = match mode {
        CompletionMode::KeepData { control, .. } => control
            .with_runtime_deadline(end, || Ok(inspect()))
            .map_err(|value| journal_control_error(value, end, Instant::now()))?,
        CompletionMode::Default { .. } => inspect(),
    };
    time(end)?;
    result
}

fn completion_guard_proof(
    journal: &Journal,
    seal: &Seal,
    guards: &mut CompletionGuards<'_>,
    end: Instant,
) -> Result<OwnedFile, Reason> {
    time(end)?;
    journal.validate_roots(end)?;
    guards
        .parent_exit
        .validate_current(&journal.root, &seal.parent_exit, &seal.policy, end)?;
    guards
        .runner_exit
        .validate_current(&journal.root, &seal.runner_exit, &seal.policy, end)?;
    validate_installation_guard(journal, guards.prefix, end)?;
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    for (guard, kind) in [
        (guards.drains.emission, LockKind::PolicyEmission),
        (guards.drains.supervisor, LockKind::Supervisor),
        (guards.drains.background, LockKind::Background),
        (
            guards.drains.purge,
            managed_purge::purge_lock_kind().map_err(|_| Reason::IdentityChanged)?,
        ),
        (guards.drains.catalog_handles, LockKind::CatalogHandles),
        (guards.drains.policy_owner, LockKind::PolicyOwner),
        (guards.history, LockKind::HistoryReaders),
    ] {
        time(end)?;
        if guard.kind() != &kind || guard.root_identity() != journal.data_identity {
            return Err(Reason::IdentityChanged);
        }
        guard
            .validate_current(root)
            .map_err(|_| Reason::IdentityChanged)?;
        time(end)?;
    }
    writer_proof(journal, guards.writer, &seal.policy, end)
}

fn validate_completion_mode(
    journal: &Journal,
    seal: &Seal,
    guards: &CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    end: Instant,
) -> Result<(), Reason> {
    time(end)?;
    match mode {
        CompletionMode::KeepData {
            control,
            installation,
        } => {
            if !journal.state.owner.keep_data {
                return Err(Reason::IdentityChanged);
            }
            validate_borrowed_keep_data_with_owner(
                journal,
                seal,
                control,
                installation,
                guards.drains.policy_owner,
                end,
            )?;
            let cleanup = control
                .lifecycle_cleanup_snapshot_with_deadline(end)
                .map_err(|value| journal_control_error(value, end, Instant::now()))?;
            if !cleanup.purge_complete() {
                return Err(Reason::PurgePrerequisitePending);
            }
            if !cleanup.backups_complete() {
                return Err(Reason::BackupCleanupPending);
            }
        }
        CompletionMode::Default { retirement } => {
            if journal.state.owner.keep_data {
                return Err(Reason::IdentityChanged);
            }
            let installation = ControlId::parse(&seal.owner.installation_id)
                .map_err(|_| Reason::IdentityChanged)?;
            let incarnation =
                ControlId::parse(&seal.catalog_incarnation).map_err(|_| Reason::IdentityChanged)?;
            let operation =
                ControlId::parse(&seal.owner.nonce).map_err(|_| Reason::IdentityChanged)?;
            retirement
                .validate_expected_binding_with_deadline(
                    journal.data_identity,
                    journal.prefix_identity,
                    RetirementBinding {
                        installation: &installation,
                        catalog_incarnation: &incarnation,
                        operation: &operation,
                    },
                    (
                        ControlSeq::new(seal.policy.control_seq)
                            .map_err(|_| Reason::IdentityChanged)?,
                        PolicyEpoch::new(seal.policy.policy_epoch)
                            .map_err(|_| Reason::IdentityChanged)?,
                    ),
                    end,
                )
                .map_err(|value| journal_control_error(value, end, Instant::now()))?;
        }
    }
    time(end)
}

fn completion_history(journal: &Journal, seal: &Seal, end: Instant) -> Result<(), Reason> {
    time(end)?;
    let latest = load_state(&journal.root, &seal.owner, end)
        .map_err(|_| {
            if Instant::now() >= end {
                Reason::Deadline
            } else {
                Reason::IdentityChanged
            }
        })?
        .ok_or(Reason::IdentityChanged)?;
    if serde_json::to_vec(&latest).map_err(|_| Reason::IdentityChanged)?
        != serde_json::to_vec(&journal.state).map_err(|_| Reason::IdentityChanged)?
        || journal.receipt_digest.is_none()
    {
        return Err(Reason::IdentityChanged);
    }
    completion_history_records(&journal.state, seal, end, |sequence| {
        let relative = format!("state-{sequence:06}.json");
        let proof = private_proof(&journal.root, &relative, &seal.policy, end)?;
        let bytes = update_state::read(&journal.root.join(relative), INVENTORY_LIMIT)
            .map_err(|_| Reason::IdentityChanged)?
            .ok_or(Reason::IdentityChanged)?;
        if format!("{:x}", Sha256::digest(&bytes)) != proof.digest {
            return Err(Reason::IdentityChanged);
        }
        verify(&journal.root, &proof, &seal.policy, end, false)?;
        Ok(bytes)
    })
}

fn completion_history_records(
    latest: &DeferredCleanup,
    seal: &Seal,
    end: Instant,
    mut read: impl FnMut(u64) -> Result<Vec<u8>, Reason>,
) -> Result<(), Reason> {
    let mut previous: Option<DeferredCleanup> = None;
    for sequence in 1..=latest.sequence {
        time(end)?;
        let bytes = read(sequence)?;
        let state: DeferredCleanup =
            serde_json::from_slice(&bytes).map_err(|_| Reason::IdentityChanged)?;
        if state.schema != STATE_SCHEMA
            || state.owner != seal.owner
            || state.sequence != sequence
            || state.catalog_incarnation != seal.catalog_incarnation
            || state.catalog_file_identity != latest.catalog_file_identity
            || state.package_manifest_sha256 != seal.package_manifest_sha256
        {
            return Err(Reason::IdentityChanged);
        }
        if let Some(plan) = &state.after_exit {
            plan.validate(&state)?;
            for (recorded, sealed) in [
                (&plan.runner, &seal.runner),
                (&plan.parent_exit, &seal.parent_exit),
                (&plan.runner_exit, &seal.runner_exit),
                (&plan.manifest, &seal.manifest),
                (
                    &plan.seal,
                    &latest
                        .after_exit
                        .as_ref()
                        .ok_or(Reason::IdentityChanged)?
                        .seal,
                ),
            ] {
                if serde_json::to_vec(recorded).map_err(|_| Reason::IdentityChanged)?
                    != serde_json::to_vec(sealed).map_err(|_| Reason::IdentityChanged)?
                {
                    return Err(Reason::IdentityChanged);
                }
            }
            if serde_json::to_vec(&state.terminal_policy).map_err(|_| Reason::IdentityChanged)?
                != serde_json::to_vec(&Some(&seal.policy)).map_err(|_| Reason::IdentityChanged)?
                || serde_json::to_vec(&state.package_files).map_err(|_| Reason::IdentityChanged)?
                    != serde_json::to_vec(&seal.package_files)
                        .map_err(|_| Reason::IdentityChanged)?
                || serde_json::to_vec(&state.private_metadata)
                    .map_err(|_| Reason::IdentityChanged)?
                    != serde_json::to_vec(&seal.metadata).map_err(|_| Reason::IdentityChanged)?
            {
                return Err(Reason::IdentityChanged);
            }
        }
        if let Some(prior) = &previous {
            if prior.after_exit.is_some() && state.after_exit.is_none()
                || prior.purge_prerequisite_complete && !state.purge_prerequisite_complete
                || prior.control_retired && !state.control_retired
                || prior.groups.len() > state.groups.len()
            {
                return Err(Reason::IdentityChanged);
            }
            for (old, new) in prior.groups.iter().zip(&state.groups) {
                if old.kind != new.kind
                    || old.removed && !new.removed
                    || serde_json::to_vec(&old.files).map_err(|_| Reason::IdentityChanged)?
                        != serde_json::to_vec(&new.files).map_err(|_| Reason::IdentityChanged)?
                {
                    return Err(Reason::IdentityChanged);
                }
            }
        }
        previous = Some(state);
    }
    time(end)
}

fn completion_prerequisites(
    state: &DeferredCleanup,
    seal: &Seal,
    end: Instant,
) -> Result<(), Reason> {
    let report = &state.report;
    let plan = state
        .after_exit
        .as_ref()
        .ok_or(Reason::AfterExitCleanupPending)?;
    if !state.purge_prerequisite_complete {
        return Err(Reason::PurgePrerequisitePending);
    }
    if !seal.metadata.classified || report.private_metadata_cleanup_pending {
        return Err(Reason::PrivateMetadataCleanupPending);
    }
    if !report.continuation_cache_cleared {
        return Err(Reason::CacheCleanupPending);
    }
    if !plan.payload_complete || report.package_cleanup_pending {
        return Err(Reason::AfterExitCleanupPending);
    }
    if !report.installation_bound
        || !report.maintenance_fenced
        || !report.private_cleanup_receipt_recorded
        || report.keep_data != state.owner.keep_data
        || !report.emission_drained
        || !report.supervisor_drained
        || !report.background_drained
        || !report.purge_owner_drained
        || !report.catalog_drained
        || !report.writer_drained
    {
        return Err(Reason::IdentityChanged);
    }
    if report.control_cleanup_pending
        || if state.owner.keep_data {
            state.control_retired || report.corpus_removed || !report.catalog_and_policy_retained
        } else {
            !state.retirement_intent_captured || !state.control_retired || !report.corpus_removed
        }
    {
        return Err(Reason::ControlCleanupPending);
    }
    time(end)
}

fn precompletion_receipt(journal: &Journal, seal: &Seal, end: Instant) -> Result<(), Reason> {
    completion_prerequisites(&journal.state, seal, end)?;
    let report = &journal.state.report;
    let plan = journal
        .state
        .after_exit
        .as_ref()
        .ok_or(Reason::IdentityChanged)?;
    if !report.after_exit_cleanup_pending
        || !report.cleanup_pending
        || report.status != "pending_cleanup"
        || plan.tail.is_some()
        || plan.tail_pending
        || plan.tail_handoff_sequence.is_some()
        || report.reasons.iter().any(|reason| {
            !matches!(
                reason,
                Reason::AfterExitCleanupPending | Reason::OwnedAfterExitHelperRequired
            )
        })
    {
        return Err(Reason::AfterExitCleanupPending);
    }
    time(end)
}

fn completed_receipt(journal: &Journal, seal: &Seal, end: Instant) -> Result<Option<u64>, Reason> {
    completed_receipt_records(&journal.state, seal, end, |sequence| {
        validated_tail_result(journal, seal, sequence, end)
    })
}

fn completed_receipt_records(
    state: &DeferredCleanup,
    seal: &Seal,
    end: Instant,
    mut tail: impl FnMut(u64) -> Result<Option<TailReceiptCompletion>, Reason>,
) -> Result<Option<u64>, Reason> {
    completion_prerequisites(state, seal, end)?;
    let report = &state.report;
    let plan = state.after_exit.as_ref().ok_or(Reason::IdentityChanged)?;
    let tail_sequence = if let Some(sequence) = plan.tail_handoff_sequence {
        if !cfg!(windows)
            || plan.tail.is_none()
            || tail(sequence)? != Some(TailReceiptCompletion::Complete)
        {
            return Err(Reason::AfterExitCleanupPending);
        }
        Some(sequence)
    } else {
        if plan.tail_pending || report.after_exit_cleanup_pending || report.cleanup_pending {
            return Err(Reason::AfterExitCleanupPending);
        }
        None
    };
    // The complete Windows acknowledgement can discharge only the old tail
    // reasons. Other pending work never becomes complete by report projection.
    if report.reasons.iter().any(|reason| {
        tail_sequence.is_none()
            || !matches!(
                reason,
                Reason::AfterExitCleanupPending | Reason::OwnedAfterExitHelperRequired
            )
    }) {
        return Err(Reason::AfterExitCleanupPending);
    }
    time(end)?;
    Ok(tail_sequence)
}

fn require_absent(
    base: &Path,
    proof: &OwnedFile,
    policy: &TerminalPolicy,
    reason: Reason,
    end: Instant,
) -> Result<(), Reason> {
    if verify(base, proof, policy, end, true)? {
        return Err(reason);
    }
    time(end)
}

fn completed_payload_absent(journal: &Journal, seal: &Seal, end: Instant) -> Result<(), Reason> {
    completed_payload_at(
        &journal.prefix,
        &journal.catalog,
        &journal.root,
        &journal.state,
        seal,
        end,
    )
}

fn completed_payload_at(
    prefix: &Path,
    catalog: &Path,
    journal_root: &Path,
    state: &DeferredCleanup,
    seal: &Seal,
    end: Instant,
) -> Result<(), Reason> {
    let root = catalog.parent().ok_or(Reason::IdentityChanged)?;
    for proof in &seal.package_files {
        require_absent(
            prefix,
            proof,
            &seal.policy,
            Reason::AfterExitCleanupPending,
            end,
        )?;
    }
    for proof in &seal.metadata.removable {
        require_absent(
            root,
            proof,
            &seal.policy,
            Reason::PrivateMetadataCleanupPending,
            end,
        )?;
    }
    for proof in seal
        .metadata
        .preserved
        .iter()
        .chain(&seal.metadata.retained)
    {
        verify(root, proof, &seal.policy, end, false)?;
    }
    for group in &state.groups {
        if !group.removed {
            return Err(match group.kind {
                GroupKind::Corpus => Reason::CorpusCleanupPending,
                GroupKind::Cache => Reason::CacheCleanupPending,
                GroupKind::Backup => Reason::BackupCleanupPending,
                GroupKind::Control => Reason::ControlCleanupPending,
            });
        }
        for proof in &group.files {
            require_absent(
                root,
                proof,
                &seal.policy,
                Reason::AfterExitCleanupPending,
                end,
            )?;
        }
    }
    if !state.owner.keep_data {
        // A forged group list cannot hide a surviving main database or sibling.
        for main in [catalog, SqliteControlStore::path(root).as_path()] {
            for suffix in ["", "-wal", "-shm"] {
                let name = format!(
                    "{}{suffix}",
                    main.file_name()
                        .and_then(OsStr::to_str)
                        .ok_or(Reason::IdentityChanged)?
                );
                time(end)?;
                match fs::symlink_metadata(root.join(name)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(Reason::FileLocked),
                    Ok(_) => return Err(Reason::CorpusCleanupPending),
                }
            }
        }
    }
    require_absent(
        journal_root,
        &seal.runner,
        &seal.policy,
        Reason::AfterExitCleanupPending,
        end,
    )?;
    if let Some(tail) = &seal.tail {
        require_absent(
            journal_root,
            tail,
            &seal.policy,
            Reason::AfterExitCleanupPending,
            end,
        )?;
    }
    Ok(())
}

fn completion_inventory_evidence(
    files: &mut BTreeMap<String, Option<CompletionFile>>,
    scope: &str,
    root: &Path,
    proofs: &[OwnedFile],
    end: Instant,
) -> Result<(), Reason> {
    for proof in proofs {
        time(end)?;
        let value = match fs::symlink_metadata(root.join(&proof.relative)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(Reason::FileLocked),
            Ok(_) => Some(CompletionFile {
                identity: proof.identity,
                size: proof.size,
                sha256: (!proof.relative.ends_with("-shm")).then(|| proof.digest.clone()),
            }),
        };
        if files
            .insert(format!("{scope}/{}", proof.relative), value)
            .is_some()
        {
            return Err(Reason::IdentityChanged);
        }
    }
    time(end)
}

fn completion_pass(
    journal: &Journal,
    guards: &mut CompletionGuards<'_>,
    mode: &CompletionMode<'_, '_>,
    receipt: CompletionReceiptCheck,
    end: Instant,
) -> Result<CompletionEvidence, Reason> {
    time(end)?;
    let seal = read_seal(journal, end)?;
    let writer = completion_guard_proof(journal, &seal, guards, end)?;
    validate_completion_mode(journal, &seal, guards, mode, end)?;
    completion_history(journal, &seal, end)?;
    let tail_sequence = match receipt {
        CompletionReceiptCheck::Published => completed_receipt(journal, &seal, end)?,
        CompletionReceiptCheck::BeforePublication => {
            precompletion_receipt(journal, &seal, end)?;
            None
        }
    };
    completed_payload_absent(journal, &seal, end)?;
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    let private = private_inventory(
        journal,
        &seal,
        matches!(mode, CompletionMode::Default { .. }),
        &writer,
        end,
    )?;
    let package = package_inventory(journal, &seal, end)?;
    if !account_tree_with_writer(root, &private, &seal.policy, Some(&writer), end)?
        || !account_tree(&journal.prefix, &package, &seal.policy, end)?
    {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    let mut files = BTreeMap::new();
    completion_inventory_evidence(&mut files, "data", root, &private, end)?;
    completion_inventory_evidence(&mut files, "prefix", &journal.prefix, &package, end)?;
    let after_writer = completion_guard_proof(journal, &seal, guards, end)?;
    if writer.identity != after_writer.identity
        || writer.digest != after_writer.digest
        || writer.size != after_writer.size
    {
        return Err(Reason::IdentityChanged);
    }
    validate_completion_mode(journal, &seal, guards, mode, end)?;
    read_seal(journal, end)?;
    time(end)?;
    Ok(CompletionEvidence {
        roots: seal.roots,
        sequence: journal.state.sequence,
        tail_sequence,
        files,
    })
}

fn finalize(
    journal: &mut Journal,
    seal: &Seal,
    installation: &ExclusiveGuard,
    parent_exit: &ExitGuard,
    runner_exit: &ExitGuard,
    end: Instant,
) -> Result<(), Reason> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    validate_installation_guard(journal, installation, end)?;
    require_completed_path(journal)?;
    let mut guards = drain_owners(journal, end)?;
    let kept_control = if journal.state.owner.keep_data {
        Some(
            SqliteControlStore::open_current_read_only_with_deadline(
                journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
                end,
            )
            .map_err(|value| journal_control_error(value, end, Instant::now()))?,
        )
    } else {
        None
    };
    let kept_installation = kept_control
        .as_ref()
        .map(|control| {
            control
                .with_runtime_deadline(end, || {
                    control.bind_installation(&journal.prefix, installation)
                })
                .map_err(|value| journal_control_error(value, end, Instant::now()))
        })
        .transpose()?;
    if let (Some(control), Some(authority)) = (&kept_control, &kept_installation) {
        validate_borrowed_keep_data(journal, seal, control, authority, &guards, end)?;
    }
    let (drains, writer) = guards.split_for_completion();
    let writer_proof = writer_proof(journal, writer, &seal.policy, end)?;
    let history = acquire(
        journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
        LockKind::HistoryReaders,
        end,
        Reason::PrivateMetadataCleanupPending,
    )?;
    if !journal.state.purge_prerequisite_complete {
        return Err(Reason::PurgePrerequisitePending);
    }
    let control_retirement = if journal.state.owner.keep_data {
        if !journal.state.report.continuation_cache_cleared {
            return Err(Reason::CacheCleanupPending);
        }
        None
    } else {
        let binding = RetirementBinding {
            installation: &ControlId::parse(&seal.owner.installation_id)
                .map_err(|_| Reason::IdentityChanged)?,
            catalog_incarnation: &ControlId::parse(&seal.catalog_incarnation)
                .map_err(|_| Reason::IdentityChanged)?,
            operation: &ControlId::parse(&seal.owner.nonce).map_err(|_| Reason::IdentityChanged)?,
        };
        let retirement = ControlRetirement::try_resume_with_deadline(
            journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
            &journal.prefix,
            installation,
            binding,
            drains,
            end,
        )
        .map_err(|_| Reason::ControlHandleDrainRequired)?;
        Some(retirement)
    };
    // An already completed input receives the strict read-only proof. It is
    // never republished merely to validate its current evidence.
    if !journal.state.report.cleanup_pending && !journal.state.report.after_exit_cleanup_pending {
        let mode = match (&kept_control, &kept_installation, &control_retirement) {
            (Some(control), Some(installation), None) => CompletionMode::KeepData {
                control,
                installation,
            },
            (None, None, Some(retirement)) => CompletionMode::Default { retirement },
            _ => return Err(Reason::IdentityChanged),
        };
        let mut completion_guards = CompletionGuards {
            parent_exit,
            runner_exit,
            prefix: installation,
            drains,
            writer,
            history: &history,
        };
        let mut completed =
            inspect_completed_uninstall(journal, &mut completion_guards, &mode, end)?;
        return completed.validate_current();
    }
    if let Some(retirement) = &control_retirement {
        terminal_cleanup(journal, retirement, end)?;
    }
    if !seal.metadata.classified {
        return Err(Reason::PrivateMetadataCleanupPending);
    }
    {
        for proof in &seal.metadata.removable {
            remove_planned(
                journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
                proof,
                journal,
                seal,
                control_retirement.as_ref(),
                end,
            )?;
        }
    }
    for proof in &seal.metadata.preserved {
        verify(
            journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
            proof,
            &seal.policy,
            end,
            false,
        )?;
    }
    journal.state.report.preserved_private_artifacts = seal.metadata.preserved.len() as u64;
    if !account_private(
        journal,
        seal,
        control_retirement.as_ref(),
        &writer_proof,
        end,
    )? {
        return Err(Reason::PrivateMetadataCleanupPending);
    }
    journal.state.report.private_metadata_cleanup_pending = false;
    journal
        .state
        .report
        .reasons
        .retain(|reason| !matches!(reason, Reason::PrivateMetadataCleanupPending));
    #[cfg(windows)]
    if journal
        .state
        .after_exit
        .as_ref()
        .is_none_or(|plan| plan.tail.is_none())
    {
        return Err(Reason::OwnedAfterExitHelperRequired);
    }
    // Non-image payloads first. Retain public/native recovery entry until every
    // ordinary payload and metadata step has a durable successful receipt.
    let mut files = seal.package_files.clone();
    files.sort_by_key(|proof| {
        (
            proof.relative.ends_with(".exe")
                || !proof.relative.contains('.') && !proof.relative.contains('/'),
            proof.relative.clone(),
        )
    });
    for proof in &files {
        remove_planned(
            &journal.prefix,
            proof,
            journal,
            seal,
            control_retirement.as_ref(),
            end,
        )?;
    }
    if !account_package(journal, seal, end)? {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    journal.state.report.package_cleanup_pending = false;
    journal
        .state
        .report
        .reasons
        .retain(|reason| !matches!(reason, Reason::UnclassifiedOwnedArtifact));
    if let Some(plan) = journal.state.after_exit.as_mut() {
        plan.payload_complete = true;
    }
    journal
        .save(end)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    if cfg!(windows) {
        // Preserve the existing close-before-capture ordering: the tail records
        // retained database bytes only after this coordinator's reader closes.
        drop(kept_control);
        #[cfg(windows)]
        launch_tail(journal, seal, control_retirement.as_ref(), end)?;
    } else {
        #[cfg(unix)]
        {
            let runner = journal
                .state
                .after_exit
                .as_ref()
                .ok_or(Reason::IdentityChanged)?
                .runner
                .clone();
            remove_planned(
                &journal.root,
                &runner,
                journal,
                seal,
                control_retirement.as_ref(),
                end,
            )?;
        }
        // The asynchronous Windows tail still owns pending work. This production
        // caller preflights the pending receipt while all original drains live.
        let mode = match (&kept_control, &kept_installation, &control_retirement) {
            (Some(control), Some(installation), None) => CompletionMode::KeepData {
                control,
                installation,
            },
            (None, None, Some(retirement)) => CompletionMode::Default { retirement },
            _ => return Err(Reason::IdentityChanged),
        };
        let mut completion_guards = CompletionGuards {
            parent_exit,
            runner_exit,
            prefix: installation,
            drains,
            writer,
            history: &history,
        };
        preflight_uninstall_completion(journal, &mut completion_guards, &mode, end)?;
        journal.publish_completion(end)?;
    }
    Ok(())
}

fn require_completed_path(journal: &Journal) -> Result<(), Reason> {
    if !journal.state.report.path_cleanup_complete()
        || journal
            .state
            .report
            .reasons
            .contains(&Reason::PathConfigurationRetained)
    {
        return Err(Reason::PathConfigurationRetained);
    }
    Ok(())
}

#[cfg(windows)]
fn launch_tail(
    journal: &mut Journal,
    seal: &Seal,
    retirement: Option<&ControlRetirement<'_>>,
    end: Instant,
) -> Result<(), Reason> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut plan = journal
        .state
        .after_exit
        .clone()
        .ok_or(Reason::IdentityChanged)?;
    let tail = plan
        .tail
        .as_ref()
        .ok_or(Reason::OwnedAfterExitHelperRequired)?;
    let source = seal
        .tail_source
        .as_ref()
        .ok_or(Reason::OwnedAfterExitHelperRequired)?;
    verify(&journal.root, source, &seal.policy, end, false)?;
    if !verify(&journal.root, tail, &seal.policy, end, true)? {
        copy_verified(
            &journal.root,
            source,
            &journal.root,
            &tail.relative,
            &seal.policy,
            false,
            end,
        )?;
        let restored = private_proof(&journal.root, &tail.relative, &seal.policy, end)?;
        plan.tail = Some(restored);
    }
    let tail = plan.tail.as_ref().ok_or(Reason::IdentityChanged)?;
    verify(&journal.root, tail, &seal.policy, end, false)?;
    plan.installation_lock = Some(private_proof(
        &journal.prefix,
        INSTALLATION_LOCK,
        &seal.policy,
        end,
    )?);
    let data = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    plan.data_locks.clear();
    plan.retained_data.clear();
    for relative in DATA_LOCKS {
        let proof = private_proof(data, relative, &seal.policy, end)?;
        if proof.size != 0 || proof.digest != EMPTY_SHA {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
        plan.data_locks.push(proof);
    }
    if let Some(retirement) = retirement {
        retirement
            .validate_marker()
            .map_err(|_| Reason::IdentityChanged)?;
        plan.retirement_marker = Some(private_proof(data, RETIREMENT_MARKER, &seal.policy, end)?);
    } else {
        let control = SqliteControlStore::open_current_read_only_with_deadline(data, end)
            .map_err(|_| Reason::IdentityChanged)?;
        let policy = journal.validate(&control, end)?;
        if policy.policy_epoch.get() != seal.policy.policy_epoch {
            return Err(Reason::MaintenanceConflict);
        }
        drop(control);
        for path in [&journal.catalog, &SqliteControlStore::path(data)] {
            let relative = path
                .strip_prefix(data)
                .map_err(|_| Reason::IdentityChanged)?;
            plan.retained_data.push(private_proof(
                data,
                relative.to_str().ok_or(Reason::IdentityChanged)?,
                &seal.policy,
                end,
            )?);
        }
    }
    plan.tail_pending = true;
    plan.tail_handoff_sequence = Some(
        journal
            .state
            .sequence
            .checked_add(1)
            .ok_or(Reason::IdentityChanged)?,
    );
    journal.state.after_exit = Some(plan.clone());
    journal.state.report.after_exit_cleanup_pending = true;
    journal
        .state
        .report
        .pending(Reason::AfterExitCleanupPending);
    journal
        .save(end)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    let system = system_powershell()?;
    let program =
        package_installation::pinned(&system).map_err(|_| Reason::OwnedAfterExitHelperRequired)?;
    let tail = plan.tail.as_ref().ok_or(Reason::IdentityChanged)?;
    let script = package_installation::pinned(&journal.root.join(&tail.relative))
        .map_err(|_| Reason::FileChanged)?;
    verify(&journal.root, tail, &seal.policy, end, false)?;
    let args = [
        OsString::from("-NoLogo"),
        OsString::from("-NoProfile"),
        OsString::from("-NonInteractive"),
        OsString::from("-File"),
        OsString::from(
            CanonicalLocator::from_path(&journal.root.join(&tail.relative))
                .map_err(|_| Reason::IdentityChanged)?
                .as_str(),
        ),
        OsString::from("-Prefix"),
        journal.prefix.as_os_str().into(),
        OsString::from("-Catalog"),
        journal.catalog.as_os_str().into(),
        OsString::from("-Nonce"),
        plan.nonce.into(),
        OsString::from("-DeadlineTick"),
        plan.deadline_tick
            .ok_or(Reason::Deadline)?
            .to_string()
            .into(),
        OsString::from("-ReceiptSequence"),
        journal.state.sequence.to_string().into(),
        OsString::from("-ReceiptSha256"),
        journal
            .receipt_digest
            .clone()
            .ok_or(Reason::IdentityChanged)?
            .into(),
        OsString::from("-SealSha256"),
        plan.seal.digest.into(),
    ];
    time(end)?;
    let child = Command::new(&system)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|_| Reason::OwnedAfterExitHelperRequired)?;
    // Prevent image/script replacement until the native runner exits. The child
    // gets no inherited capability; it waits for the separate exact owner lock.
    std::mem::forget(script);
    std::mem::forget(program);
    drop(child);
    Ok(())
}
#[cfg(windows)]
fn system_powershell() -> Result<PathBuf, Reason> {
    package_installation::system_powershell().map_err(|_| Reason::OwnedAfterExitHelperRequired)
}

/// A finite inventory check is not removal authority. Only ancestors of bound
/// files are traversed; any extra file/linked directory remains pending.
fn account_tree(
    root: &Path,
    proofs: &[OwnedFile],
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<bool, Reason> {
    account_tree_with_writer(root, proofs, policy, None, end)
}
fn account_tree_with_writer(
    root: &Path,
    proofs: &[OwnedFile],
    policy: &TerminalPolicy,
    writer: Option<&OwnedFile>,
    end: Instant,
) -> Result<bool, Reason> {
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    for proof in proofs {
        if !package_installation::safe_member(&proof.relative)
            || files
                .insert(PathBuf::from(&proof.relative), proof)
                .is_some()
        {
            return Err(Reason::IdentityChanged);
        }
        let mut parent = Path::new(&proof.relative).parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    let mut pending = vec![PathBuf::new()];
    let mut count = 0;
    while let Some(relative) = pending.pop() {
        time(end)?;
        let absolute = root.join(&relative);
        package_installation::ordinary(&absolute).map_err(|_| Reason::IdentityChanged)?;
        let directory = platform::directory(&absolute).map_err(|_| Reason::IdentityChanged)?;
        for entry in fs::read_dir(&absolute).map_err(|_| Reason::FileLocked)? {
            time(end)?;
            count += 1;
            if count > MAX_ENTRIES {
                return Ok(false);
            }
            let entry = entry.map_err(|_| Reason::FileLocked)?;
            let path = relative.join(entry.file_name());
            let meta = fs::symlink_metadata(entry.path()).map_err(|_| Reason::FileLocked)?;
            let linked = meta.file_type().is_symlink();
            #[cfg(windows)]
            let linked = {
                use std::os::windows::fs::MetadataExt;
                linked || meta.file_attributes() & 0x400 != 0
            };
            if linked {
                return Ok(false);
            }
            if meta.is_dir() {
                if !directories.contains(&path) {
                    return Ok(false);
                }
                pending.push(path);
            } else if meta.is_file() {
                let Some(proof) = files.get(&path) else {
                    return Ok(false);
                };
                if writer.is_some_and(|held| {
                    held.relative == proof.relative && held.identity == proof.identity
                }) {
                    let file =
                        platform::open_file(&entry.path()).map_err(|_| Reason::FileLocked)?;
                    if platform::identity(&file).map_err(|_| Reason::FileChanged)? != proof.identity
                        || file.metadata().map_err(|_| Reason::FileChanged)?.len() != proof.size
                    {
                        return Err(Reason::FileChanged);
                    }
                } else {
                    verify(root, proof, policy, end, false)?;
                }
            } else {
                return Ok(false);
            }
        }
        if platform::identity(&directory).map_err(|_| Reason::IdentityChanged)?
            != platform::identity(
                &platform::directory(&absolute).map_err(|_| Reason::IdentityChanged)?,
            )
            .map_err(|_| Reason::IdentityChanged)?
        {
            return Err(Reason::IdentityChanged);
        }
    }
    Ok(true)
}
fn writer_proof(
    journal: &Journal,
    writer: &mut WriterLease,
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<OwnedFile, Reason> {
    writer_proof_with_open(journal, writer, policy, end, |path| {
        platform::open_file(path).map_err(|_| Reason::FileLocked)
    })
}

fn writer_proof_with_open(
    journal: &Journal,
    writer: &mut WriterLease,
    policy: &TerminalPolicy,
    end: Instant,
    open_file: impl FnOnce(&Path) -> Result<fs::File, Reason>,
) -> Result<OwnedFile, Reason> {
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    writer_proof_at(root, journal.data_identity, writer, policy, end, open_file)
}

fn writer_proof_at(
    root: &Path,
    root_identity: RootIdentity,
    writer: &mut WriterLease,
    policy: &TerminalPolicy,
    end: Instant,
    open_file: impl FnOnce(&Path) -> Result<fs::File, Reason>,
) -> Result<OwnedFile, Reason> {
    time(end)?;
    if writer.path() != root.join("writer.lock")
        || RootIdentity::read(root).map_err(|_| Reason::IdentityChanged)? != root_identity
        || policy.overlaps(writer.path())?
    {
        return Err(Reason::IdentityChanged);
    }
    writer
        .validate_current(root)
        .map_err(|_| Reason::IdentityChanged)?;
    // Read diagnostics through the held lease handle. Windows denies a second
    // byte-reading handle while this actual exclusive lock remains live.
    let record = writer.read_record().map_err(|_| Reason::FileLocked)?;
    if record.len() > 1024 {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    let file = open_file(writer.path())?;
    if file.metadata().map_err(|_| Reason::FileChanged)?.len() != record.len() as u64 {
        return Err(Reason::FileChanged);
    }
    let proof = OwnedFile {
        relative: "writer.lock".into(),
        digest: format!("{:x}", Sha256::digest(record.as_bytes())),
        size: record.len() as u64,
        identity: platform::identity(&file).map_err(|_| Reason::FileChanged)?,
    };
    // A name can switch A -> B -> A between the current-name checks. Bind the
    // actual proof handle to the same retained handle that supplied the record.
    writer
        .validate_proof_file(&file)
        .map_err(|_| Reason::IdentityChanged)?;
    writer
        .validate_current(root)
        .map_err(|_| Reason::IdentityChanged)?;
    if RootIdentity::read(root).map_err(|_| Reason::IdentityChanged)? != root_identity {
        return Err(Reason::IdentityChanged);
    }
    time(end)?;
    Ok(proof)
}
fn account_private(
    journal: &Journal,
    seal: &Seal,
    retirement: Option<&ControlRetirement<'_>>,
    writer: &OwnedFile,
    end: Instant,
) -> Result<bool, Reason> {
    if let Some(retirement) = retirement {
        retirement
            .validate_marker()
            .map_err(|_| Reason::IdentityChanged)?;
    } else if journal.state.owner.keep_data {
        validate_keep_fence(journal, &seal.policy, end)?;
    }
    let proofs = private_inventory(journal, seal, retirement.is_some(), writer, end)?;
    account_tree_with_writer(
        journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
        &proofs,
        &seal.policy,
        Some(writer),
        end,
    )
}

/// Construct only the finite inventory. Callers retain their own mode/connection
/// validation; this helper never opens a control connection or resumes retirement.
fn private_inventory(
    journal: &Journal,
    seal: &Seal,
    retired: bool,
    writer: &OwnedFile,
    end: Instant,
) -> Result<Vec<OwnedFile>, Reason> {
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    let mut proofs = Vec::new();
    for proof in seal
        .metadata
        .preserved
        .iter()
        .chain(&seal.metadata.retained)
    {
        if proof.relative.ends_with(".lock") {
            if proof.size != 0 || proof.digest != EMPTY_SHA {
                return Err(Reason::IdentityChanged);
            }
            // A rendezvous can be created by a drain after the initial inventory,
            // but the existing bound inode and empty contents still have to match.
            if verify(root, proof, &seal.policy, end, true)? {
                proofs.push(proof.clone());
            }
        } else if verify(root, proof, &seal.policy, end, true)? {
            proofs.push(proof.clone());
        }
    }
    for relative in EMPTY_RENDEZVOUS {
        if proofs.iter().any(|proof| proof.relative == *relative) {
            continue;
        }
        if fs::symlink_metadata(root.join(relative)).is_ok() {
            let proof = private_proof(root, relative, &seal.policy, end)?;
            if proof.size != 0 || proof.digest != EMPTY_SHA {
                return Err(Reason::UnclassifiedOwnedArtifact);
            }
            proofs.push(proof);
        }
    }
    if retired {
        proofs.push(private_proof(root, RETIREMENT_MARKER, &seal.policy, end)?);
    } else if journal.state.owner.keep_data {
        let control_path = SqliteControlStore::path(root);
        let catalog_proof =
            private_proof(root, &journal.state.owner.catalog_name, &seal.policy, end)?;
        let control_proof = private_proof(root, "control.db", &seal.policy, end)?;
        if catalog_proof.identity != journal.state.catalog_file_identity
            || control_proof.identity != seal.policy.control_file_identity
        {
            return Err(Reason::IdentityChanged);
        }
        proofs.extend([catalog_proof, control_proof]);
        // SQLite siblings never gain deletion authority. Their existing read-only
        // handles and schema/identity-qualified parent connection justify retention.
        for main in [&journal.catalog, &control_path] {
            for suffix in ["-wal", "-shm"] {
                let name = format!(
                    "{}{}",
                    main.file_name()
                        .and_then(OsStr::to_str)
                        .ok_or(Reason::IdentityChanged)?,
                    suffix
                );
                if fs::symlink_metadata(root.join(&name)).is_ok() {
                    proofs.push(private_proof(root, &name, &seal.policy, end)?);
                }
            }
        }
    }
    // Writer lease contents are diagnostics, not process authority. The real
    // acquired writer capability protects this exact inode through the check.
    proofs.push(writer.clone());
    for group in &journal.state.groups {
        if group.removed {
            continue;
        }
        for proof in &group.files {
            if verify(root, proof, &seal.policy, end, true)? {
                proofs.push(proof.clone());
            }
        }
    }
    // Empty, verified owned group parents are intentionally kept; account_tree
    // still needs their planned coordinates after their payload was removed.
    for group in &journal.state.groups {
        for proof in &group.files {
            if !proof.relative.contains('/') {
                continue;
            }
            if !proofs.iter().any(|item| item.relative == proof.relative) {
                proofs.push(proof.clone());
            }
        }
    }
    Ok(proofs)
}
fn account_package(journal: &Journal, seal: &Seal, end: Instant) -> Result<bool, Reason> {
    let proofs = package_inventory(journal, seal, end)?;
    account_tree(&journal.prefix, &proofs, &seal.policy, end)
}
fn package_inventory(
    journal: &Journal,
    seal: &Seal,
    end: Instant,
) -> Result<Vec<OwnedFile>, Reason> {
    let mut proofs = seal.package_files.clone();
    proofs.push(private_proof(
        &journal.prefix,
        INSTALLATION_LOCK,
        &seal.policy,
        end,
    )?);
    for entry in fs::read_dir(&journal.root).map_err(|_| Reason::FileLocked)? {
        time(end)?;
        let entry = entry.map_err(|_| Reason::FileLocked)?;
        if entry.file_name() == "helper" {
            continue;
        }
        let name = entry
            .file_name()
            .to_str()
            .ok_or(Reason::IdentityChanged)?
            .to_owned();
        if name != "owner.json" {
            let number = name
                .strip_prefix("state-")
                .and_then(|n| n.strip_suffix(".json"))
                .filter(|n| n.len() == 6)
                .and_then(|n| n.parse::<u64>().ok())
                .filter(|n| *n > 0 && *n <= journal.state.sequence)
                .ok_or(Reason::UnclassifiedOwnedArtifact)?;
            let bytes = update_state::read(&entry.path(), INVENTORY_LIMIT)
                .map_err(|_| Reason::IdentityChanged)?
                .ok_or(Reason::IdentityChanged)?;
            let state: DeferredCleanup =
                serde_json::from_slice(&bytes).map_err(|_| Reason::IdentityChanged)?;
            if state.schema != STATE_SCHEMA || state.owner != seal.owner || state.sequence != number
            {
                return Err(Reason::IdentityChanged);
            }
        }
        let mut proof = private_proof(&journal.root, &name, &seal.policy, end)?;
        proof.relative = format!("uninstall/{name}");
        proofs.push(proof);
    }
    let plan = journal
        .state
        .after_exit
        .as_ref()
        .ok_or(Reason::IdentityChanged)?;
    for proof in tail_result_proofs(journal, seal, end)? {
        let mut proof = proof;
        proof.relative = format!("uninstall/{}", proof.relative);
        proofs.push(proof);
    }
    for proof in [
        &plan.runner,
        &plan.parent_exit,
        &plan.runner_exit,
        &plan.manifest,
        &plan.seal,
    ]
    .into_iter()
    .chain(plan.tail.iter())
    .chain(seal.tail_source.iter())
    {
        let mut proof = proof.clone();
        proof.relative = format!("uninstall/{}", proof.relative);
        proofs.push(proof);
    }
    Ok(proofs)
}

fn clear_completed_reasons(report: &mut Report) {
    report.reasons.retain(|reason| match reason {
        Reason::AfterExitCleanupPending | Reason::OwnedAfterExitHelperRequired => {
            report.after_exit_cleanup_pending
        }
        Reason::PrivateMetadataCleanupPending => report.private_metadata_cleanup_pending,
        Reason::CorpusCleanupPending => !report.keep_data && !report.corpus_removed,
        Reason::CacheCleanupPending => !report.continuation_cache_cleared,
        Reason::ControlCleanupPending | Reason::ControlHandleDrainRequired => {
            report.control_cleanup_pending
        }
        Reason::UnclassifiedOwnedArtifact => {
            report.package_cleanup_pending || report.private_metadata_cleanup_pending
        }
        _ => true,
    });
    report.cleanup_pending = report.after_exit_cleanup_pending
        || report.package_cleanup_pending
        || report.private_metadata_cleanup_pending
        || report.control_cleanup_pending
        || !report.reasons.is_empty();
    if !report.cleanup_pending {
        report.status = "complete_with_retained_private_markers".into();
    }
}
fn validated_tail_result(
    journal: &Journal,
    seal: &Seal,
    sequence: u64,
    end: Instant,
) -> Result<Option<TailReceiptCompletion>, Reason> {
    if sequence == 0 || sequence > journal.state.sequence {
        return Err(Reason::IdentityChanged);
    }
    let relative = format!("helper/tail-result-{sequence:06}.json");
    let Some(bytes) = update_state::read(&journal.root.join(&relative), 8192)
        .map_err(|_| Reason::IdentityChanged)?
    else {
        return Ok(None);
    };
    let result: TailResult = serde_json::from_slice(&bytes).map_err(|_| Reason::IdentityChanged)?;
    let receipt_bytes = update_state::read(
        &journal.root.join(format!("state-{sequence:06}.json")),
        INVENTORY_LIMIT,
    )
    .map_err(|_| Reason::IdentityChanged)?
    .ok_or(Reason::IdentityChanged)?;
    let completion = classify_tail_receipt(&result, &receipt_bytes, &seal.owner, sequence)?;
    let _proof = private_proof(&journal.root, &relative, &seal.policy, end)?;
    Ok(Some(completion))
}

/// Classify the decoded tail against exact old state bytes without I/O.
/// Live absence, root, policy and inventory checks remain in the inspector.
fn classify_tail_receipt(
    result: &TailResult,
    receipt_bytes: &[u8],
    owner: &Owner,
    sequence: u64,
) -> Result<TailReceiptCompletion, Reason> {
    let state: DeferredCleanup =
        serde_json::from_slice(receipt_bytes).map_err(|_| Reason::IdentityChanged)?;
    let plan = state.after_exit.as_ref().ok_or(Reason::IdentityChanged)?;
    if result.schema != "asg.uninstall-tail-result/v1"
        || result.nonce != owner.nonce
        || result.seal_sha256 != plan.seal.digest
        || result.receipt_sequence != sequence
        || result.receipt_sha256 != format!("{:x}", Sha256::digest(receipt_bytes))
        || Some(result.deadline_tick) != plan.deadline_tick
        || plan.tail_handoff_sequence != Some(sequence)
        || !plan.payload_complete
        || !plan.tail_pending
        || &state.owner != owner
        || state.sequence != sequence
        || !matches!(
            result.reason.as_str(),
            "complete" | "tail_cleanup_pending" | "runner_cleanup_pending" | "identity_changed"
        )
        || result.complete != (result.tail_removed && result.runner_removed)
        || (result.complete && result.reason != "complete")
    {
        return Err(Reason::IdentityChanged);
    }
    Ok(if result.complete {
        TailReceiptCompletion::Complete
    } else {
        TailReceiptCompletion::Pending
    })
}
fn tail_result_proofs(
    journal: &Journal,
    seal: &Seal,
    end: Instant,
) -> Result<Vec<OwnedFile>, Reason> {
    let mut proofs = Vec::new();
    for (count, entry) in fs::read_dir(journal.root.join("helper"))
        .map_err(|_| Reason::IdentityChanged)?
        .enumerate()
    {
        time(end)?;
        if count >= MAX_STATES as usize + 8 {
            return Err(Reason::UnclassifiedOwnedArtifact);
        }
        let entry = entry.map_err(|_| Reason::IdentityChanged)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(Reason::IdentityChanged)?
            .to_owned();
        if !name.starts_with("tail-result-") {
            continue;
        }
        let sequence = name
            .strip_prefix("tail-result-")
            .and_then(|value| value.strip_suffix(".json"))
            .filter(|n| n.len() == 6)
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or(Reason::IdentityChanged)?;
        validated_tail_result(journal, seal, sequence, end)?.ok_or(Reason::IdentityChanged)?;
        proofs.push(private_proof(
            &journal.root,
            &format!("helper/{name}"),
            &seal.policy,
            end,
        )?);
    }
    Ok(proofs)
}
/// Read-only inspection for the existing tail recovery path. The returned
/// report is an in-memory projection, not a reinstall or lock capability.
/// In particular, default recovery still accepts its existing pending marker;
/// completed-only admission needs separate published-marker and borrowed-guard
/// validation before it can authorize any new lifecycle.
fn inspect_tail_completion(
    journal: &Journal,
    seal: &Seal,
    end: Instant,
) -> Result<Option<Report>, Reason> {
    let plan = journal
        .state
        .after_exit
        .as_ref()
        .ok_or(Reason::AfterExitCleanupPending)?;
    let Some(sequence) = plan.tail_handoff_sequence else {
        return Ok(None);
    };
    let Some(completion) = validated_tail_result(journal, seal, sequence, end)? else {
        return Ok(None);
    };
    if completion != TailReceiptCompletion::Complete {
        return Ok(None);
    }
    // Observed absence is necessary in addition to the durable acknowledgement.
    // A replaced helper image, unknown file or new owner keeps cleanup Pending.
    let tail = plan
        .tail
        .as_ref()
        .ok_or(Reason::OwnedAfterExitHelperRequired)?;
    if verify(&journal.root, &plan.runner, &seal.policy, end, true)?
        || verify(&journal.root, tail, &seal.policy, end, true)?
    {
        return Err(Reason::AfterExitCleanupPending);
    }
    journal.validate_roots(end)?;
    if journal.state.owner.keep_data {
        validate_keep_fence(journal, &seal.policy, end)?;
    } else {
        validate_retired_receipt(
            journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
            &journal.state,
            end,
        )
        .map_err(|_| Reason::IdentityChanged)?;
    }
    if !account_package(journal, seal, end)? {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    let mut report = journal.state.report.clone();
    report.after_exit_cleanup_pending = false;
    report.recovery_entry_recorded = false;
    clear_completed_reasons(&mut report);
    Ok(Some(report))
}

fn consume_tail_result(journal: &mut Journal, seal: &Seal, end: Instant) -> Result<bool, Reason> {
    let Some(report) = inspect_tail_completion(journal, seal, end)? else {
        return Ok(false);
    };
    journal.state.report = report;
    if let Some(plan) = journal.state.after_exit.as_mut() {
        plan.tail_pending = false;
    }
    journal
        .save(end)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    Ok(true)
}
/// Called before package verification on an explicit repeat. The sealed native
/// runner remains the recovery entry even after package payloads have gone.
pub(super) fn recover_public(
    catalog: &Path,
    prefix: &Path,
    keep_data: bool,
    end: Instant,
) -> Result<Option<Report>, CliError> {
    let Some(state) = read_deferred_cleanup(prefix, catalog, end)? else {
        return Ok(None);
    };
    if state.owner.keep_data != keep_data {
        return Err(error(CanonicalCode::InvalidRequest));
    }
    // An older partial plan does not bypass the unfinished native PATH
    // transaction. Re-enter the package-verified coordinator with its nonce.
    if !state.report.path_cleanup_complete()
        || state
            .report
            .reasons
            .contains(&Reason::PathConfigurationRetained)
    {
        return Ok(None);
    }
    if state.after_exit.is_none() {
        return Ok(None);
    }
    let mut journal = open_journal(prefix, catalog, end)?;
    let installation = update_state::acquire_installation_lock(prefix, end)?;
    let result = (|| -> Result<bool, Reason> {
        let seal = read_seal(&journal, end)?;
        if consume_tail_result(&mut journal, &seal, end)? {
            return Ok(true);
        }
        let plan = journal
            .state
            .after_exit
            .clone()
            .ok_or(Reason::AfterExitCleanupPending)?;
        verify(&journal.root, &plan.runner, &seal.policy, end, false)?;
        Ok(false)
    })();
    drop(installation);
    match result {
        Ok(true) => Ok(Some(journal.state.report)),
        Ok(false) => schedule(
            catalog
                .to_str()
                .ok_or_else(|| error(CanonicalCode::InvalidRequest))?,
            Some(prefix.into()),
            end,
        )
        .map(Some),
        Err(reason) => {
            journal.state.report.pending(reason);
            journal.save_before_deadline(end)?;
            Ok(Some(journal.state.report))
        }
    }
}

/// Read through the caller's sealed connection and real held guards. The
/// snapshot grants no continuing cleanup authority.
fn validate_borrowed_keep_data(
    journal: &Journal,
    seal: &Seal,
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    guards: &CleanupGuards,
    end: Instant,
) -> Result<(), Reason> {
    validate_borrowed_keep_data_with_owner(
        journal,
        seal,
        control,
        installation,
        &guards.policy_owner,
        end,
    )
}

fn validate_borrowed_keep_data_with_owner(
    journal: &Journal,
    seal: &Seal,
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    policy_owner: &ExclusiveGuard,
    end: Instant,
) -> Result<(), Reason> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    time(end)?;
    let control_error = |value| journal_control_error(value, end, Instant::now());
    // Carry CLI refusals separately from adapter errors. The existing scope
    // owns the final tick, busy allowance and SQL-handler reset, also on unwind.
    let inspect = || {
        #[cfg(test)]
        tests::before_borrowed_keep_data_check(tests::BorrowedKeepDataCheck::Roots)
            .map_err(control_error)?;
        journal.validate_roots(end)?;
        time(end)?;
        #[cfg(test)]
        tests::before_borrowed_keep_data_check(tests::BorrowedKeepDataCheck::Control)
            .map_err(control_error)?;
        let owner = control
            .bind_control_root(policy_owner)
            .map_err(control_error)?;
        let status = control
            .read_bound_to_sealed_with_deadline(
                journal.data_identity,
                &owner,
                installation,
                SealedControlFile::from_recorded(seal.policy.control_file_identity),
                end,
            )
            .map_err(control_error)?;
        time(end)?;
        validate_keep_status(&journal.state, seal, &status, installation)?;
        time(end)?;
        #[cfg(test)]
        tests::before_borrowed_keep_data_check(tests::BorrowedKeepDataCheck::Catalog)
            .map_err(control_error)?;
        let file =
            platform::open_file(&journal.catalog).map_err(|_| Reason::CorpusCleanupPending)?;
        if platform::identity(&file).map_err(|_| Reason::IdentityChanged)?
            != journal.state.catalog_file_identity
        {
            return Err(Reason::IdentityChanged);
        }
        time(end)
    };
    control
        .with_runtime_deadline(end, || Ok(inspect()))
        .map_err(control_error)?
}

fn validate_keep_status(
    state: &DeferredCleanup,
    seal: &Seal,
    status: &ControlStatus,
    installation: &InstallationLockAuthority<'_>,
) -> Result<(), Reason> {
    let policy = &status.policy;
    if !state.owner.keep_data
        || seal.owner != state.owner
        || policy.installation_id.as_str() != state.owner.installation_id
        || &policy.installation_id != installation.installation_id()
        || seal.catalog_incarnation != state.catalog_incarnation
        || status.catalog_incarnation.as_ref().map(ControlId::as_str)
            != Some(seal.catalog_incarnation.as_str())
        || policy.maintenance.state != MaintenanceState::Uninstalling
        || policy.maintenance.owner.as_ref().map(ControlId::as_str)
            != Some(state.owner.nonce.as_str())
        || policy.control_seq.get() != seal.policy.control_seq
        || policy.policy_epoch.get() != seal.policy.policy_epoch
        || serde_json::to_vec(&terminal_regions(policy)).map_err(|_| Reason::MaintenanceConflict)?
            != serde_json::to_vec(&seal.policy.regions).map_err(|_| Reason::MaintenanceConflict)?
    {
        return Err(Reason::MaintenanceConflict);
    }
    Ok(())
}

fn validate_keep_fence(
    journal: &Journal,
    policy: &TerminalPolicy,
    end: Instant,
) -> Result<(), Reason> {
    journal.validate_roots(end)?;
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    let control = SqliteControlStore::open_current_read_only_with_deadline(root, end)
        .map_err(|_| Reason::IdentityChanged)?;
    let fresh = journal.validate(&control, end)?;
    let current = TerminalPolicy::capture(&fresh, root)?;
    if current.policy_epoch != policy.policy_epoch
        || current.control_seq != policy.control_seq
        || current.control_file_identity != policy.control_file_identity
        || serde_json::to_vec(&current.regions).ok() != serde_json::to_vec(&policy.regions).ok()
    {
        return Err(Reason::MaintenanceConflict);
    }
    let file = platform::open_file(&journal.catalog).map_err(|_| Reason::CorpusCleanupPending)?;
    if platform::identity(&file).map_err(|_| Reason::IdentityChanged)?
        != journal.state.catalog_file_identity
    {
        return Err(Reason::IdentityChanged);
    }
    Ok(())
}
fn remove_planned(
    base: &Path,
    proof: &OwnedFile,
    journal: &Journal,
    seal: &Seal,
    retirement: Option<&ControlRetirement<'_>>,
    end: Instant,
) -> Result<(), Reason> {
    loop {
        journal.validate_roots(end)?;
        if let Some(retirement) = retirement {
            retirement
                .validate_marker()
                .map_err(|_| Reason::IdentityChanged)?;
        } else if journal.state.owner.keep_data {
            validate_keep_fence(journal, &seal.policy, end)?;
        }
        if !verify(base, proof, &seal.policy, end, true)? {
            return Ok(());
        }
        match remove_exact(base, proof, &seal.policy, end) {
            Ok(()) => {
                platform::sync_directory(
                    base.join(&proof.relative)
                        .parent()
                        .ok_or(Reason::IdentityChanged)?,
                )
                .map_err(|_| Reason::FileLocked)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                time(end)?;
                std::thread::sleep(
                    Duration::from_millis(10).min(end.saturating_duration_since(Instant::now())),
                );
            }
            Err(_) => return Err(Reason::FileLocked),
        }
    }
}

/// Windows hashes and deletes through one deny-write/deny-replacement handle.
/// Unix rechecks the named inode under every owned root/drain immediately before
/// unlink; held catalog/control gates forbid unlinking any open managed SQLite.
fn remove_exact(
    base: &Path,
    proof: &OwnedFile,
    policy: &TerminalPolicy,
    end: Instant,
) -> std::io::Result<()> {
    #[cfg(test)]
    observe_cleanup_admission(CleanupAdmissionEvent::BeforeDelete, end);
    let invalid = |_| std::io::Error::other("owned cleanup identity changed");
    verify(base, proof, policy, end, false).map_err(invalid)?;
    let path = base.join(&proof.relative);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_DISPOSITION_INFO, FileDispositionInfo,
            GetFileInformationByHandle, SetFileInformationByHandle,
        };
        let mut file = std::fs::OpenOptions::new()
            .access_mode(0x80000000 | 0x00010000)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&path)?;
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, info.as_mut_ptr()) } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let info = unsafe { info.assume_init() };
        if info.nNumberOfLinks != 1
            || info.dwFileAttributes & (0x400 | 0x10) != 0
            || platform::identity(&file)? != proof.identity
            || file.metadata()?.len() != proof.size
        {
            return Err(std::io::Error::other("owned cleanup identity changed"));
        }
        let mut sha = Sha256::new();
        let mut count = 0u64;
        let mut bytes = [0; 65536];
        loop {
            time(end).map_err(invalid)?;
            let n = file.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            if count > proof.size {
                return Err(std::io::Error::other("owned cleanup changed"));
            }
            sha.update(&bytes[..n]);
        }
        if count != proof.size || format!("{:x}", sha.finalize()) != proof.digest {
            return Err(std::io::Error::other("owned cleanup changed"));
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as _,
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        drop(file);
        Ok(())
    }
    #[cfg(unix)]
    {
        let pinned = platform::open_file(&path)?;
        if platform::identity(&pinned)? != proof.identity {
            return Err(std::io::Error::other("owned cleanup changed"));
        }
        verify(base, proof, policy, end, false).map_err(invalid)?;
        fs::remove_file(path)
    }
}

fn deadline_tick(end: Instant) -> Result<u64, Reason> {
    time(end)?;
    monotonic_ms()?
        .checked_add(
            end.saturating_duration_since(Instant::now())
                .as_millis()
                .try_into()
                .map_err(|_| Reason::Deadline)?,
        )
        .ok_or(Reason::Deadline)
}
fn end_from_tick(tick: u64) -> Result<Instant, Reason> {
    let remaining = tick
        .checked_sub(monotonic_ms()?)
        .filter(|remaining| *remaining > 0 && *remaining <= BUDGET.as_millis() as u64)
        .ok_or(Reason::Deadline)?;
    Ok(Instant::now() + Duration::from_millis(remaining))
}
fn monotonic_ms() -> Result<u64, Reason> {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetTickCount64() -> u64;
        }
        Ok(unsafe { GetTickCount64() })
    }
    #[cfg(unix)]
    {
        let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
            return Err(Reason::Deadline);
        }
        let time = unsafe { time.assume_init() };
        (time.tv_sec as u64)
            .checked_mul(1000)
            .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64 / 1_000_000))
            .ok_or(Reason::Deadline)
    }
}

#[cfg(test)]
#[path = "managed_uninstall_cleanup_tests.rs"]
mod tests;
