//! Private after-exit cleanup. Plans grant no wildcard/path or process authority.
//! The native parent retains one noninheritable OS lock until process exit; the
//! child must acquire that SAME inode before changing any planned payload file.
use super::*;
use agent_session_grep_adapters_sqlite::managed_purge::PrivateArtifactClass;
use std::io::Write;

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
    "catalog-handles.lock",
    "history-readers.lock",
    "background.lock",
    "supervisor.lock",
    "maintenance-job-6f776e65642d7075726765.lock",
];
const EMPTY_RENDEZVOUS: &[&str] = &[
    "policy-owner.lock",
    "policy-emission.lock",
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
    let seal: Seal = serde_json::from_slice(&bytes).map_err(|_| Reason::IdentityChanged)?;
    if seal.schema != SEAL_SCHEMA
        || seal.owner != journal.state.owner
        || seal.roots != RootPins::capture(journal)?
        || seal.catalog_incarnation != journal.state.catalog_incarnation
        || seal.package_manifest_sha256 != journal.state.package_manifest_sha256
        || serde_json::to_vec(&seal.package_files).ok()
            != serde_json::to_vec(&journal.state.package_files).ok()
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
            != serde_json::to_vec(&journal.state.private_metadata).ok()
    {
        return Err(Reason::IdentityChanged);
    }
    verify(&journal.root, &seal.owner_file, policy, end, false)?;
    let manifest_bytes =
        update_state::read(&journal.root.join(&plan.manifest.relative), INVENTORY_LIMIT)
            .map_err(|_| Reason::IdentityChanged)?
            .ok_or(Reason::IdentityChanged)?;
    let manifest = Manifest::parse(&manifest_bytes).map_err(|_| Reason::IdentityChanged)?;
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
fn exit_lock(
    base: &Path,
    proof: &OwnedFile,
    policy: &TerminalPolicy,
    end: Instant,
    wait: bool,
) -> Result<File, Reason> {
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
                let current = platform::open_file(&path).map_err(|_| Reason::FileChanged)?;
                if platform::identity(&current).map_err(|_| Reason::FileChanged)? != proof.identity
                    || file.metadata().map_err(|_| Reason::FileChanged)?.len() != 0
                {
                    return Err(Reason::FileChanged);
                }
                return Ok(file);
            }
            Err(fs::TryLockError::WouldBlock) if wait => {
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
    let running = std::env::current_exe().map_err(|_| Reason::IdentityChanged)?;
    if fs::canonicalize(&running).map_err(|_| Reason::IdentityChanged)?
        != fs::canonicalize(journal.root.join(&plan.runner.relative))
            .map_err(|_| Reason::IdentityChanged)?
    {
        return Err(Reason::IdentityChanged);
    }
    verify(&journal.root, &plan.runner, &seal.policy, end, false)?;
    let _parent_exited = exit_lock(&journal.root, &plan.parent_exit, &seal.policy, end, true)?;
    let runner_owner = exit_lock(&journal.root, &plan.runner_exit, &seal.policy, end, false)?;
    let installation = update_state::acquire_installation_lock(prefix, end)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    if recover {
        plan.deadline_tick = Some(tick);
        journal.state.after_exit = Some(plan);
    }
    let result = if consume_tail_result(&mut journal, &seal, end)? {
        Ok(())
    } else {
        finalize(&mut journal, &seal, &installation, end)
    };
    if let Err(reason) = &result {
        journal.state.report.pending(*reason);
    }
    if result.is_ok() && cfg!(windows) {
        // launch_tail already flushed its exact handoff receipt. Writing another
        // would sever the tail's sequence/digest binding to that durable intent.
        std::mem::forget(runner_owner);
    } else {
        journal
            .save_before_deadline(end)
            .map_err(|_| Reason::AfterExitCleanupPending)?;
    }
    result
}
fn finalize(
    journal: &mut Journal,
    seal: &Seal,
    installation: &ExclusiveGuard,
    end: Instant,
) -> Result<(), Reason> {
    let mut guards = drain_owners(journal, end)?;
    let writer_proof = writer_proof(journal, &mut guards._writer, &seal.policy, end)?;
    let _history = acquire(
        journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
        LockKind::HistoryReaders,
        end,
        Reason::PrivateMetadataCleanupPending,
    )?;
    if !journal.state.purge_prerequisite_complete {
        return Err(Reason::PurgePrerequisitePending);
    }
    let control_retirement = if journal.state.owner.keep_data {
        let control = SqliteControlStore::open_current_read_only_with_deadline(
            journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
            end,
        )
        .map_err(|_| Reason::IdentityChanged)?;
        journal.validate(&control, end)?;
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
        let retirement = ControlRetirement::try_resume(
            journal.catalog.parent().ok_or(Reason::IdentityChanged)?,
            &journal.prefix,
            installation,
            binding,
            guards.retirement(),
        )
        .map_err(|_| Reason::ControlHandleDrainRequired)?;
        terminal_cleanup(journal, &retirement, end)?;
        Some(retirement)
    };
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
    #[cfg(windows)]
    {
        launch_tail(journal, seal, control_retirement.as_ref(), end)
    }
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
        journal.state.report.after_exit_cleanup_pending = false;
        journal.state.report.reasons.retain(|reason| {
            !matches!(
                reason,
                Reason::OwnedAfterExitHelperRequired | Reason::AfterExitCleanupPending
            )
        });
        journal.state.report.cleanup_pending = !journal.state.report.reasons.is_empty();
        if !journal.state.report.cleanup_pending {
            journal.state.report.status = "complete_with_retained_private_markers".into();
        }
        journal
            .save(end)
            .map_err(|_| Reason::AfterExitCleanupPending)
    }
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
    time(end)?;
    let root = journal.catalog.parent().ok_or(Reason::IdentityChanged)?;
    if writer.path() != root.join("writer.lock") || policy.overlaps(writer.path())? {
        return Err(Reason::IdentityChanged);
    }
    // Read diagnostics through the held lease handle. Windows denies a second
    // byte-reading handle while this actual exclusive lock remains live.
    let record = writer.read_record().map_err(|_| Reason::FileLocked)?;
    if record.len() > 1024 {
        return Err(Reason::UnclassifiedOwnedArtifact);
    }
    let file = platform::open_file(writer.path()).map_err(|_| Reason::FileLocked)?;
    if file.metadata().map_err(|_| Reason::FileChanged)?.len() != record.len() as u64 {
        return Err(Reason::FileChanged);
    }
    Ok(OwnedFile {
        relative: "writer.lock".into(),
        digest: format!("{:x}", Sha256::digest(record.as_bytes())),
        size: record.len() as u64,
        identity: platform::identity(&file).map_err(|_| Reason::FileChanged)?,
    })
}
fn account_private(
    journal: &Journal,
    seal: &Seal,
    retirement: Option<&ControlRetirement<'_>>,
    writer: &OwnedFile,
    end: Instant,
) -> Result<bool, Reason> {
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
    if let Some(retirement) = retirement {
        retirement
            .validate_marker()
            .map_err(|_| Reason::IdentityChanged)?;
        proofs.push(private_proof(root, RETIREMENT_MARKER, &seal.policy, end)?);
    } else if journal.state.owner.keep_data {
        validate_keep_fence(journal, &seal.policy, end)?;
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
    account_tree_with_writer(root, &proofs, &seal.policy, Some(writer), end)
}
fn account_package(journal: &Journal, seal: &Seal, end: Instant) -> Result<bool, Reason> {
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
    account_tree(&journal.prefix, &proofs, &seal.policy, end)
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
) -> Result<Option<TailResult>, Reason> {
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
    let state: DeferredCleanup =
        serde_json::from_slice(&receipt_bytes).map_err(|_| Reason::IdentityChanged)?;
    let plan = state.after_exit.as_ref().ok_or(Reason::IdentityChanged)?;
    if result.schema != "asg.uninstall-tail-result/v1"
        || result.nonce != seal.owner.nonce
        || result.seal_sha256 != plan.seal.digest
        || result.receipt_sequence != sequence
        || result.receipt_sha256 != format!("{:x}", Sha256::digest(&receipt_bytes))
        || Some(result.deadline_tick) != plan.deadline_tick
        || plan.tail_handoff_sequence != Some(sequence)
        || !plan.payload_complete
        || !plan.tail_pending
        || state.owner != seal.owner
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
    let _proof = private_proof(&journal.root, &relative, &seal.policy, end)?;
    Ok(Some(result))
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
fn consume_tail_result(journal: &mut Journal, seal: &Seal, end: Instant) -> Result<bool, Reason> {
    let plan = journal
        .state
        .after_exit
        .clone()
        .ok_or(Reason::AfterExitCleanupPending)?;
    let Some(sequence) = plan.tail_handoff_sequence else {
        return Ok(false);
    };
    let Some(result) = validated_tail_result(journal, seal, sequence, end)? else {
        return Ok(false);
    };
    if !result.complete {
        return Ok(false);
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
    journal.state.report.after_exit_cleanup_pending = false;
    journal.state.report.recovery_entry_recorded = false;
    if let Some(plan) = journal.state.after_exit.as_mut() {
        plan.tail_pending = false;
    }
    clear_completed_reasons(&mut journal.state.report);
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
