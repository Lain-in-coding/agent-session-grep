//! Automatic owned withdrawal cleanup, independent of update pause/stop.
//! The private worker never opens provider histories or emits transcript data.
use crate::{ProtocolError, app_clock_ms, managed_background::DetachedChild};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, RootIdentity},
    managed_purge::{
        ClassifiedPrivateArtifact, PrivateArtifactClass, PrivateArtifactInventory, PurgeStage,
        purge_lock_kind,
    },
    managed_store::validate_catalog_path,
};
use agent_session_grep_ports::{
    PortError, PortResult,
    control::{ControlId, ControlStore, MaintenanceState, PurgeState},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const CHILD: &str = "__managed-purge";
const SLICE_BUDGET: Duration = Duration::from_secs(5);
const CONTROL_BUDGET: Duration = Duration::from_millis(250);

/// Physical cleanup after a catalog purge commits is whole-file work: FTS
/// `optimize`, four `integrity-check` passes and `VACUUM` cannot be split, and
/// they scale with the catalog. On a 1.9 GiB catalog they need ~45 s on a fast
/// NVMe host, so a fixed 5 s slice was interrupted at the deadline, rolled
/// back, and retried forever while holding the catalog, writer and emission
/// locks. Once the catalog stage reports pending, the next slice is sized from
/// the catalog bytes with a conservative throughput floor and doubles on each
/// further miss up to a hard cap.
const CATALOG_SLICE_FLOOR_MIB_PER_SECOND: u64 = 10;
const CATALOG_SLICE_OVERHEAD: Duration = Duration::from_secs(10);
const CATALOG_SLICE_MAX: Duration = Duration::from_secs(30 * 60);

fn next_catalog_slice(previous: Duration, bytes: u64) -> Duration {
    let mib = bytes.saturating_add((1 << 20) - 1) >> 20;
    let estimated = CATALOG_SLICE_OVERHEAD.saturating_add(Duration::from_secs(
        mib / CATALOG_SLICE_FLOOR_MIB_PER_SECOND.max(1),
    ));
    previous
        .saturating_mul(2)
        .max(estimated)
        .max(SLICE_BUDGET)
        .min(CATALOG_SLICE_MAX)
}

fn catalog_bytes(catalog: &Path) -> u64 {
    let mut total = fs::metadata(catalog).map_or(0, |m| m.len());
    let mut wal = catalog.as_os_str().to_os_string();
    wal.push("-wal");
    total = total.saturating_add(fs::metadata(PathBuf::from(wal)).map_or(0, |m| m.len()));
    total
}

fn check_control_deadline(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(PortError::WriterBusy(
            "owned purge control deadline reached".into(),
        ))
    } else {
        Ok(())
    }
}
fn check_root(root: &Path, expected: RootIdentity) -> PortResult<()> {
    if RootIdentity::read(root)? != expected {
        return Err(PortError::GenerationMismatch(
            "owned purge control root changed".into(),
        ));
    }
    Ok(())
}
fn retry_busy_before<T>(
    deadline: Instant,
    mut operation: impl FnMut() -> PortResult<T>,
) -> PortResult<T> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    loop {
        check_control_deadline(deadline)?;
        match operation() {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            result => return result,
        }
    }
}
fn control_before<T>(
    control: &SqliteControlStore,
    deadline: Instant,
    mut operation: impl FnMut() -> PortResult<T>,
) -> PortResult<T> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    retry_busy_before(deadline, || {
        control.with_runtime_deadline(deadline, &mut operation)
    })
}
fn read_before(
    root: &Path,
    physical: RootIdentity,
    deadline: Instant,
) -> PortResult<SqliteControlStore> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    retry_busy_before(deadline, || {
        check_root(root, physical)?;
        let control = SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
        check_root(root, physical)?;
        Ok(control)
    })
}
fn open_before(root: &Path, deadline: Instant) -> PortResult<SqliteControlStore> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    check_control_deadline(deadline)?;
    let physical = RootIdentity::read(root)?;
    let witness = read_before(root, physical, deadline)?;
    let installation = control_before(&witness, deadline, || witness.status())?
        .policy
        .installation_id;
    drop(witness);
    retry_busy_before(deadline, || {
        check_root(root, physical)?;
        let control = SqliteControlStore::open_existing_writable_with_deadline(
            root,
            &installation,
            deadline,
        )?;
        check_root(root, physical)?;
        control.with_runtime_deadline(deadline, || {
            if control.status()?.policy.installation_id != installation {
                return Err(PortError::GenerationMismatch(
                    "owned purge installation changed".into(),
                ));
            }
            Ok(())
        })?;
        Ok(control)
    })
}
fn invalid() -> PortError {
    PortError::InvalidRequest("invalid owned purge request".into())
}
fn fresh() -> PortResult<ControlId> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| invalid())?;
    ControlId::parse(&format!(
        "purge_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}
pub(crate) fn intercept(args: &[OsString]) -> Option<i32> {
    if args.first().is_none_or(|a| a != CHILD) {
        return None;
    }
    Some(if args.len() != 3 || args[1] != "--db" {
        2
    } else {
        match run_child(Path::new(&args[2])) {
            Ok(()) => 0,
            Err(e) => ProtocolError::from_private_port_error(e).code.exit_code(),
        }
    })
}
/// Startup acknowledgement is separate from completion; durable jobs are the
/// authority. A busy existing owner is not treated as a completed purge.
pub(crate) fn ensure_started(catalog: &Path, deadline: Instant) -> Value {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    let attempt = || -> PortResult<Value> {
        if Instant::now() >= deadline {
            return Ok(json!({"requested":false,"pending":true,"reason":"deadline"}));
        }
        validate_catalog_path(catalog)?;
        let root = catalog.parent().ok_or_else(invalid)?;
        let physical = RootIdentity::read(root)?;
        let control = read_before(root, physical, deadline)?;
        let (status, pending) = control_before(&control, deadline, || {
            Ok((
                control.status()?,
                control
                    .purge_jobs()?
                    .iter()
                    .any(|j| j.state != PurgeState::Complete),
            ))
        })?;
        if !pending {
            return Ok(json!({"requested":false,"pending":false}));
        }
        if status.catalog_incarnation.is_none() {
            return Ok(
                json!({"requested":false,"pending":true,"reason":"catalog_not_initialized"}),
            );
        }
        if status.policy.maintenance.state != MaintenanceState::Idle {
            return Ok(
                json!({"requested":false,"pending":true,"reason":"installation_maintenance"}),
            );
        }
        match ExclusiveGuard::try_acquire(root, purge_lock_kind()?) {
            Ok(guard) => drop(guard),
            Err(PortError::WriterBusy(_)) => {
                return Ok(json!({"requested":false,"pending":true,"reason":"owner_present"}));
            }
            Err(e) => return Err(e),
        }
        check_control_deadline(deadline)?;
        let executable = std::env::current_exe().map_err(|_| invalid())?;
        let mut child = DetachedChild::spawn_for(&executable, catalog, CHILD)?;
        let end = deadline.min(Instant::now() + Duration::from_millis(500));
        loop {
            if child.try_wait()?.is_some() {
                return Ok(
                    json!({"requested":true,"pending":true,"reason":"worker_finished_or_failed"}),
                );
            }
            match ExclusiveGuard::try_acquire(root, purge_lock_kind()?) {
                Err(PortError::WriterBusy(_)) => {
                    return Ok(json!({"requested":true,"pending":true,"reason":"owner_observed"}));
                }
                Ok(guard) => drop(guard),
                Err(e) => return Err(e),
            }
            if Instant::now() >= end {
                return Ok(json!({"requested":true,"pending":true,"reason":"startup_pending"}));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    attempt().unwrap_or_else(
        |_| json!({"requested":false,"pending":true,"reason":"startup_unavailable"}),
    )
}
fn run_child(catalog: &Path) -> PortResult<()> {
    let startup_end = SqliteControlStore::effective_runtime_deadline(Instant::now() + SLICE_BUDGET);
    validate_catalog_path(catalog)?;
    let root = catalog.parent().ok_or_else(invalid)?;
    let control = open_before(root, startup_end)?;
    if control_before(&control, startup_end, || control.status())?
        .catalog_incarnation
        .is_none()
    {
        return Ok(());
    }
    let guard = match ExclusiveGuard::try_acquire(root, purge_lock_kind()?) {
        Ok(guard) => guard,
        Err(PortError::WriterBusy(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    let nonce = fresh()?;
    let owner = control_before(&control, startup_end, || {
        control.bind_purge_owner(&guard, nonce.clone())
    })?;
    let mut slice = SLICE_BUDGET;
    loop {
        let end = SqliteControlStore::effective_runtime_deadline(Instant::now() + slice);
        check_control_deadline(end)?;
        let report = run_slice(&control, catalog, &owner, end);
        let pause = match report {
            Ok(None) => return Ok(()),
            Ok(Some(report)) if report.complete() => return Ok(()),
            Ok(Some(report)) if matches!(report.catalog, PurgeStage::Pending(_)) => {
                slice = next_catalog_slice(slice, catalog_bytes(catalog));
                Duration::from_secs(2)
            }
            Ok(_) => {
                slice = SLICE_BUDGET;
                Duration::from_secs(10)
            }
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                Duration::from_secs(2)
            }
            Err(e) => return Err(e),
        };
        if wait_for_next_slice(&control, Instant::now() + pause)? {
            return Ok(());
        }
    }
}
fn run_slice(
    control: &SqliteControlStore,
    catalog: &Path,
    owner: &agent_session_grep_adapters_sqlite::control::PurgeOwner<'_>,
    deadline: Instant,
) -> PortResult<Option<agent_session_grep_adapters_sqlite::managed_purge::PurgeReport>> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    // Admission, private inventory and all adapter stages share this slice's
    // original end. A retry is a later slice of the same durable jobs/OS owner.
    control.with_runtime_deadline(deadline, || {
        let status = control.status()?;
        if status.policy.maintenance.state != MaintenanceState::Idle
            || control
                .purge_jobs()?
                .iter()
                .all(|j| j.state == PurgeState::Complete)
        {
            return Ok(None);
        }
        // Missing installed authority leaves rollback cleanup pending.
        let install = crate::package_installation::installation(None).ok();
        let lock = install
            .as_ref()
            .and_then(|i| crate::update_state::acquire_installation_lock(&i.prefix, deadline).ok());
        let authority = install
            .as_ref()
            .zip(lock.as_ref())
            .and_then(|(i, l)| control.bind_installation(&i.prefix, l).ok());
        let report = match artifact_inventory(control, catalog, install.as_ref(), deadline) {
            Ok(inventory) => agent_session_grep_adapters_sqlite::managed_purge::run_with_inventory(
                control,
                catalog,
                owner,
                authority.as_ref(),
                &inventory,
                app_clock_ms(),
                deadline,
            ),
            Err(error @ PortError::WriterBusy(_)) => return Err(error),
            Err(_) => agent_session_grep_adapters_sqlite::managed_purge::run(
                control,
                catalog,
                owner,
                authority.as_ref(),
                app_clock_ms(),
                deadline,
            ),
        }?;
        Ok(Some(report))
    })
}
fn wait_for_next_slice(control: &SqliteControlStore, deadline: Instant) -> PortResult<bool> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    wait_for_next_slice_with(deadline, |end| {
        control.with_runtime_deadline(end, || {
            Ok(control.status()?.policy.maintenance.state != MaintenanceState::Idle)
        })
    })
}
fn wait_for_next_slice_with(
    deadline: Instant,
    mut maintenance_requested: impl FnMut(Instant) -> PortResult<bool>,
) -> PortResult<bool> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    // A refused status tick never releases our purge lock. Real schema/root/I/O
    // failures still terminate; maintenance stops us once it can be observed.
    while Instant::now() < deadline {
        let tick_end = deadline.min(Instant::now() + CONTROL_BUDGET);
        match maintenance_requested(tick_end) {
            Ok(true) => return Ok(true),
            Ok(false) | Err(PortError::WriterBusy(_)) => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    Ok(false)
}

/// Private settings evidence. This DTO has no public serialization; even a
/// correct binding never grants history permission or file-removal authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupArtifactBinding {
    schema: String,
    installation_id: String,
    control_root_id: String,
    created_policy_epoch: i64,
}
impl SetupArtifactBinding {
    pub(crate) fn validate(
        &self,
        root: agent_session_grep_adapters_sqlite::managed_locks::RootIdentity,
        status: &agent_session_grep_ports::control::ControlStatus,
    ) -> PortResult<()> {
        if self.schema != "asg.setup-inventory-binding/v1"
            || self.installation_id != status.policy.installation_id.as_str()
            || self.control_root_id != root.control_id().as_str()
            || self.created_policy_epoch < 0
            || self.created_policy_epoch > status.policy.policy_epoch.get()
        {
            return Err(classification_error());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostInventory {
    schema: String,
    binding: SetupArtifactBinding,
    receipts: Vec<HostLocator>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostLocator {
    host: crate::host_config::Host,
    config_path: PathBuf,
    transaction_root: PathBuf,
    transaction_id: String,
    receipt_path: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeInventory {
    schema: String,
    binding: SetupArtifactBinding,
    location: crate::native_autostart::NativeLocation,
    journal_root: PathBuf,
    receipt: crate::native_autostart::AutostartReceipt,
}
fn classification_error() -> PortError {
    PortError::SchemaIncompatible("owned settings require verified classification".into())
}
fn check_inventory_deadline(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(PortError::WriterBusy(
            "owned settings classification deadline reached".into(),
        ))
    } else {
        Ok(())
    }
}
fn private_bytes(path: &Path, limit: u64, deadline: Instant) -> PortResult<Vec<u8>> {
    check_inventory_deadline(deadline)?;
    let bytes = crate::update_state::read(path, limit)
        .map_err(|_| classification_error())?
        .ok_or_else(classification_error)?;
    check_inventory_deadline(deadline)?;
    Ok(bytes)
}
fn inventory_file(
    root: &Path,
    path: &Path,
    class: PrivateArtifactClass,
    bytes: &[u8],
) -> PortResult<ClassifiedPrivateArtifact> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| classification_error())?;
    let relative = relative
        .to_str()
        .ok_or_else(classification_error)?
        .replace('\\', "/");
    ClassifiedPrivateArtifact::new(
        class,
        &relative,
        bytes.len() as u64,
        blake3::hash(bytes).to_hex().as_str(),
    )
}
/// Inspect only known settings schemas under the same captured physical root
/// and permission epoch. Unknown files remain absent from the inventory and
/// are subsequently reported UnclassifiedArtifact by the storage adapter.
/// Provider histories are never read, and no setup/PATH recovery is performed.
pub(crate) fn artifact_inventory(
    control: &SqliteControlStore,
    catalog: &Path,
    install: Option<&crate::package_installation::Installation>,
    deadline: Instant,
) -> PortResult<PrivateArtifactInventory> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    control.with_runtime_deadline(deadline, || {
        use crate::{
            native_autostart::{NativeAutostartStore, NativeLocation},
            path_command::PathArtifactClass,
        };
        use agent_session_grep_adapters_sqlite::managed_locks::RootIdentity;
        let root = catalog.parent().ok_or_else(invalid)?;
        let physical = RootIdentity::read(root)?;
        let status = control.status()?;
        let epoch = status.policy.policy_epoch;
        let mut artifacts = Vec::new();
        let mut native_seen = false;
        for (index, entry) in fs::read_dir(root)
            .map_err(|_| classification_error())?
            .enumerate()
        {
            check_inventory_deadline(deadline)?;
            if index >= 4096 {
                return Err(classification_error());
            }
            let entry = entry.map_err(|_| classification_error())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let hosts = name.starts_with("setup-hosts-");
            let native = name.starts_with("setup-autostart-");
            if !(hosts || native) {
                continue;
            }
            let bytes = private_bytes(&entry.path(), 1024 * 1024, deadline)?;
            if hosts {
                let record: HostInventory =
                    serde_json::from_slice(&bytes).map_err(|_| classification_error())?;
                record.binding.validate(physical, &status)?;
                if record.schema != "asg.setup-host-inventory/v1" || record.receipts.len() > 256 {
                    return Err(classification_error());
                }
                let install = install.ok_or_else(classification_error)?;
                for locator in record.receipts {
                    check_inventory_deadline(deadline)?;
                    let host = locator.host;
                    let locator = crate::setup_hosts::PrivateReceiptLocator {
                        host,
                        config_path: locator.config_path,
                        transaction_root: locator.transaction_root,
                        transaction_id: locator.transaction_id,
                        receipt_path: locator.receipt_path,
                    };
                    let receipt = locator.read_receipt().map_err(|_| classification_error())?;
                    let expected = crate::host_config::McpRegistration::new(
                        install
                            .launcher
                            .to_str()
                            .ok_or_else(classification_error)?
                            .into(),
                        vec![
                            "--db".into(),
                            catalog.to_str().ok_or_else(classification_error)?.into(),
                            "mcp".into(),
                        ],
                    )
                    .map_err(|_| classification_error())?
                    .value(host);
                    let hash = format!(
                        "{:x}",
                        Sha256::digest(
                            serde_json::to_vec(&expected).map_err(|_| classification_error())?
                        )
                    );
                    if receipt.owned_by_asg && receipt.owned_value_sha256.as_ref() != Some(&hash) {
                        return Err(classification_error());
                    }
                }
            } else {
                let record: NativeInventory =
                    serde_json::from_slice(&bytes).map_err(|_| classification_error())?;
                record.binding.validate(physical, &status)?;
                if record.schema != "asg.setup-autostart-inventory/v1"
                    || record.receipt.installation_id != status.policy.installation_id.as_str()
                {
                    return Err(classification_error());
                }
                let expected_root = match &record.location {
                    NativeLocation::WindowsRun { .. } => root.join("native-autostart"),
                    NativeLocation::SystemdUser { directory }
                    | NativeLocation::LaunchAgent { directory, .. } => {
                        directory.join(format!(".asg-{}", status.policy.installation_id.as_str()))
                    }
                };
                if record.journal_root != expected_root {
                    return Err(classification_error());
                }
                let store = NativeAutostartStore::open(
                    record.location,
                    &record.journal_root,
                    status.policy.installation_id.as_str(),
                )
                .map_err(|_| classification_error())?;
                let _verified_chain = store
                    .inspect_recovery()
                    .map_err(|_| classification_error())?;
                // The unique verified leaf validates every predecessor and image.
                store
                    .latest_receipt()
                    .map_err(|_| classification_error())?
                    .ok_or_else(classification_error)?;
                if record.journal_root == root.join("native-autostart") {
                    collect_native_files(root, &record.journal_root, &mut artifacts, deadline)?;
                    native_seen = true;
                }
            }
            artifacts.push(inventory_file(
                root,
                &entry.path(),
                PrivateArtifactClass::SetupInventory,
                &bytes,
            )?);
        }
        // No wrapper means no native ownership proof; leave that directory unknown.
        if !native_seen && root.join("native-autostart").exists() {
            return Err(classification_error());
        }
        let path = crate::path_command::inspect_owned_artifacts(
            root,
            physical,
            &status.policy.installation_id,
            epoch,
            deadline,
        )
        .map_err(|_| classification_error())?;
        if path.installation != status.policy.installation_id
            || path.root != physical
            || path.policy_epoch != epoch
            || path.operations > 256
            || path.pending_operations > path.operations
        {
            return Err(classification_error());
        }
        for artifact in path.artifacts {
            check_inventory_deadline(deadline)?;
            if matches!(artifact.class, PathArtifactClass::LiveUserSettings)
                || !artifact.asg_owned_container
            {
                continue;
            }
            if !artifact.matches_recorded_digest {
                // Preserved third-party settings remain external data. A changed
                // owned image is unclassified until explicit PATH recovery.
                if !path.settings_conflicts {
                    return Err(classification_error());
                }
                continue;
            }
            if !artifact.locator.starts_with(root) {
                continue;
            }
            let bytes = private_bytes(&artifact.locator, 1024 * 1024, deadline)?;
            if bytes.len() as u64 != artifact.size_bytes
                || format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256
            {
                return Err(classification_error());
            }
            artifacts.push(inventory_file(
                root,
                &artifact.locator,
                PrivateArtifactClass::UserPathRegistration,
                &bytes,
            )?);
        }
        let migration = crate::migrate_command::inspect_private_artifacts(
            catalog, control, physical, epoch, deadline,
        )
        .map_err(|_| classification_error())?;
        artifacts.extend(migration);
        let restore =
            agent_session_grep_adapters_sqlite::managed_maintenance::inspect_restore_inventory(
                control, catalog, deadline,
            )?;
        // Restore stage images are source content, never setup/settings artifacts.
        // Only completed receipts are content-free classified records. An unfinished
        // owned publication needs explicit recovery before cleanup can be complete.
        if restore.incomplete() || !restore.staged_images().is_empty() {
            return Err(classification_error());
        }
        for receipt in restore.receipts() {
            check_inventory_deadline(deadline)?;
            if !receipt.complete() {
                return Err(classification_error());
            }
            artifacts.push(ClassifiedPrivateArtifact::new(
                PrivateArtifactClass::CatalogRestoreReceipt,
                receipt.relative_locator(),
                receipt.size_bytes(),
                receipt.blake3_digest(),
            )?);
        }
        check_inventory_deadline(deadline)?;
        PrivateArtifactInventory::bind(control, physical, epoch, artifacts)
    })
}
fn collect_native_files(
    root: &Path,
    native: &Path,
    artifacts: &mut Vec<ClassifiedPrivateArtifact>,
    deadline: Instant,
) -> PortResult<()> {
    // The native schema's unique ownership chain was already verified. Still
    // enumerate every exact bounded name; an unknown sibling is not ignored.
    for (count, entry) in fs::read_dir(native)
        .map_err(|_| classification_error())?
        .enumerate()
    {
        check_inventory_deadline(deadline)?;
        if count >= 258 {
            return Err(classification_error());
        }
        let entry = entry.map_err(|_| classification_error())?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|_| classification_error())?;
        if meta.is_dir() && !meta.file_type().is_symlink() {
            crate::native_autostart::platform::validate_private(&entry.path())
                .map_err(|_| classification_error())?;
            for (index, file) in fs::read_dir(entry.path())
                .map_err(|_| classification_error())?
                .enumerate()
            {
                if index >= 4096 {
                    return Err(classification_error());
                }
                let file = file.map_err(|_| classification_error())?;
                let bytes = private_bytes(&file.path(), 16 * 1024 * 1024, deadline)?;
                artifacts.push(inventory_file(
                    root,
                    &file.path(),
                    PrivateArtifactClass::NativeRegistration,
                    &bytes,
                )?);
            }
        } else {
            let bytes = private_bytes(&entry.path(), 16384, deadline)?;
            artifacts.push(inventory_file(
                root,
                &entry.path(),
                PrivateArtifactClass::NativeRegistration,
                &bytes,
            )?);
        }
        if artifacts.len() > 4096 {
            return Err(classification_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_adapters_sqlite::{
        managed_locks::LockKind, managed_store::ManagedStore,
    };
    use agent_session_grep_ports::{SearchProvider, control::*};
    use rusqlite::Connection;
    use std::sync::mpsc;

    fn id(value: &str) -> ControlId {
        ControlId::parse(value).unwrap()
    }
    fn guard(root: &Path, kind: LockKind) -> ExclusiveGuard {
        retry_busy_before(Instant::now() + SLICE_BUDGET, || {
            ExclusiveGuard::try_acquire(root, kind.clone())
        })
        .unwrap()
    }
    struct Fixture {
        _temp: tempfile::TempDir,
        catalog: PathBuf,
        source: PathBuf,
        job: ControlId,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let root = temp.path().join("private");
            let catalog = root.join("catalog.db");
            let source = temp.path().join("synthetic-read-only.jsonl");
            fs::write(&source, b"synthetic purge source sentinel").unwrap();
            let control = SqliteControlStore::create(
                &root,
                &id("synthetic-purge-installation"),
                DesiredUpdates::Paused,
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let job = control
                .with_runtime_deadline(deadline, || {
                    let store =
                        ManagedStore::create(&catalog, &control, id("synthetic-purge-catalog"), 1)?;
                    assert!(control.status()?.catalog_incarnation.is_none());
                    {
                        let background = guard(&root, LockKind::Background);
                        let worker =
                            control.bind_worker(&background, id("synthetic-purge-bootstrap"))?;
                        control.register_worker(
                            control.status()?.policy.control_seq,
                            &worker,
                            1,
                            1,
                        )?;
                        store.reconcile_progress(&control, &worker)?;
                    }
                    assert_eq!(
                        control.status()?.catalog_incarnation,
                        Some(store.incarnation().clone())
                    );
                    drop(store);
                    let selection = control
                        .add_selection(
                            control.status()?.policy.control_seq,
                            SelectionRequest {
                                region: ScopeRegion {
                                    provider: SearchProvider::Claude,
                                    locator: CanonicalLocator::from_path(&source)?,
                                    kind: RootKind::Exact,
                                },
                                root_identity: Some(id("synthetic-purge-source-root")),
                                now_ms: 1,
                            },
                        )?
                        .value;
                    let job = control
                        .revoke_selection(
                            control.status()?.policy.control_seq,
                            &selection.id,
                            None,
                            2,
                        )?
                        .value
                        .purge_job
                        .id;
                    Ok(job)
                })
                .unwrap();
            drop(control);
            Self {
                _temp: temp,
                catalog,
                source,
                job,
            }
        }
        fn root(&self) -> &Path {
            self.catalog.parent().unwrap()
        }
        fn control(&self) -> SqliteControlStore {
            open_before(self.root(), Instant::now() + SLICE_BUDGET).unwrap()
        }
        fn assert_original(&self) {
            assert_eq!(
                fs::read(&self.source).unwrap(),
                b"synthetic purge source sentinel"
            );
        }
    }

    #[test]
    fn purge_child_retries_control_handle_admission_then_completes_original_job() {
        let fixture = Fixture::new();
        let held = guard(fixture.root(), LockKind::ControlHandles);
        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let catalog = fixture.catalog.clone();
        // Detached on purpose: run_child is the long-lived purge worker and
        // keeps retrying an incomplete job. A scoped thread would turn a
        // missed completion into a hang of the whole test binary instead of
        // this test's timeout failure.
        let child = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _ = result_tx.send(run_child(&catalog));
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        // Longer than the old 250ms control admission, still inside the
        // child's one five-second startup end. No guessed PID is involved.
        std::thread::sleep(Duration::from_millis(450));
        let before_release = result_rx.try_recv();
        drop(held);
        assert!(
            matches!(before_release, Err(mpsc::TryRecvError::Empty)),
            "purge child exited during temporary control contention"
        );
        result_rx
            .recv_timeout(Duration::from_secs(8))
            .expect("purge child did not complete the original job in time")
            .unwrap();
        child.join().unwrap();
        let control = fixture.control();
        let job = control.purge_job_status(&fixture.job).unwrap();
        assert_eq!(job.job.state, PurgeState::Complete);
        assert_eq!(job.job.attempts.get(), 1);
        assert_eq!(
            control.status().unwrap().desired_updates,
            DesiredUpdates::Paused
        );
        assert!(!control.status().unwrap().policy.exclusions.is_empty());
        fixture.assert_original();
    }

    #[test]
    fn purge_wait_defers_busy_keeps_owner_and_observes_maintenance() {
        let fixture = Fixture::new();
        let control = fixture.control();
        let held = guard(fixture.root(), purge_lock_kind().unwrap());
        let owner = control
            .bind_purge_owner(&held, id("synthetic-wait-owner"))
            .unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        let mut observations = 0;
        assert!(
            wait_for_next_slice_with(end, |tick_end| {
                assert!(tick_end <= end);
                observations += 1;
                if observations <= 2 {
                    return Err(PortError::WriterBusy(
                        "synthetic refused status tick".into(),
                    ));
                }
                control.with_runtime_deadline(tick_end, || {
                    let seq = control.status()?.policy.control_seq;
                    let maintenance = id("synthetic-maintenance-owner");
                    control.set_maintenance(
                        seq,
                        &maintenance,
                        MaintenanceFence {
                            state: MaintenanceState::Updating,
                            owner: Some(maintenance.clone()),
                            phase: Some(MaintenancePhase::Quiescing),
                        },
                    )?;
                    Ok(true)
                })
            })
            .unwrap()
        );
        assert_eq!(observations, 3);
        assert!(matches!(
            ExclusiveGuard::try_acquire(fixture.root(), purge_lock_kind().unwrap()),
            Err(PortError::WriterBusy(_))
        ));
        assert_eq!(owner.nonce(), &id("synthetic-wait-owner"));
        assert_eq!(
            control.purge_job_status(&fixture.job).unwrap().job.state,
            PurgeState::Pending
        );
        fixture.assert_original();
    }

    #[test]
    fn purge_control_contention_uses_original_end_and_later_connection_still_works() {
        let fixture = Fixture::new();
        let control = fixture.control();
        let writer = Connection::open(SqliteControlStore::path(fixture.root())).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let result = control_before(&control, started + Duration::from_millis(20), || {
            let seq = control.status()?.policy.control_seq;
            control.set_desired_updates(seq, DesiredUpdates::Stopped)
        });
        let elapsed = started.elapsed();
        writer.execute_batch("ROLLBACK").unwrap();
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(elapsed < Duration::from_millis(150), "elapsed: {elapsed:?}");
        assert_eq!(
            control.status().unwrap().desired_updates,
            DesiredUpdates::Paused
        );
        control_before(&control, Instant::now() + SLICE_BUDGET, || {
            control.set_desired_updates(
                control.status()?.policy.control_seq,
                DesiredUpdates::Stopped,
            )
        })
        .unwrap();
        assert_eq!(
            control.status().unwrap().desired_updates,
            DesiredUpdates::Stopped
        );
        assert_eq!(
            control
                .purge_job_status(&fixture.job)
                .unwrap()
                .job
                .attempts
                .get(),
            0
        );
        fixture.assert_original();
    }

    #[test]
    fn nested_purge_control_retry_uses_earlier_end_under_real_sql_contention() {
        let fixture = Fixture::new();
        let control = fixture.control();
        let writer = Connection::open(SqliteControlStore::path(fixture.root())).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let earlier = started + Duration::from_millis(20);
        let later = started + Duration::from_secs(1);
        let result = control.with_runtime_deadline(earlier, || {
            control_before(&control, later, || {
                control.set_desired_updates(
                    control.status()?.policy.control_seq,
                    DesiredUpdates::Stopped,
                )
            })
        });
        let elapsed = started.elapsed();
        writer.execute_batch("ROLLBACK").unwrap();
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(
            elapsed < Duration::from_millis(150),
            "nested retry elapsed: {elapsed:?}"
        );
        assert_eq!(
            control.status().unwrap().desired_updates,
            DesiredUpdates::Paused
        );
        assert_eq!(
            control
                .purge_job_status(&fixture.job)
                .unwrap()
                .job
                .attempts
                .get(),
            0
        );
        control_before(&control, Instant::now() + SLICE_BUDGET, || {
            control.set_desired_updates(
                control.status()?.policy.control_seq,
                DesiredUpdates::Stopped,
            )
        })
        .unwrap();
        assert_eq!(
            control.status().unwrap().desired_updates,
            DesiredUpdates::Stopped
        );
        fixture.assert_original();
    }

    #[test]
    fn nested_purge_initial_open_uses_earlier_end_under_real_handle_contention() {
        let fixture = Fixture::new();
        let scope_fixture = Fixture::new();
        let scope_control = scope_fixture.control();
        let held = guard(fixture.root(), LockKind::ControlHandles);
        let started = Instant::now();
        let result = scope_control
            .with_runtime_deadline(started + Duration::from_millis(20), || {
                open_before(fixture.root(), started + Duration::from_secs(1))
            });
        let elapsed = started.elapsed();
        drop(held);
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(
            elapsed < Duration::from_millis(150),
            "nested admission elapsed: {elapsed:?}"
        );
        let reopened = fixture.control();
        assert_eq!(
            reopened
                .purge_job_status(&fixture.job)
                .unwrap()
                .job
                .attempts
                .get(),
            0
        );
        assert_eq!(
            reopened.status().unwrap().desired_updates,
            DesiredUpdates::Paused
        );
        fixture.assert_original();
        scope_fixture.assert_original();
    }

    #[test]
    fn expired_purge_slice_refuses_before_claim_or_inventory() {
        let fixture = Fixture::new();
        let control = fixture.control();
        let held = guard(fixture.root(), purge_lock_kind().unwrap());
        let owner = control
            .bind_purge_owner(&held, id("synthetic-expired-owner"))
            .unwrap();
        assert!(matches!(
            run_slice(&control, &fixture.catalog, &owner, Instant::now()),
            Err(PortError::WriterBusy(_))
        ));
        let job = control.purge_job_status(&fixture.job).unwrap();
        assert_eq!(job.job.state, PurgeState::Pending);
        assert_eq!(job.job.attempts.get(), 0);
        fixture.assert_original();
    }

    #[test]
    fn catalog_slice_grows_for_whole_file_cleanup_and_is_capped() {
        // A tiny catalog still gets at least a doubled slice after a miss.
        assert_eq!(next_catalog_slice(SLICE_BUDGET, 0), Duration::from_secs(10));
        // 1.9 GiB of catalog needs ~190 s at the conservative 10 MiB/s floor,
        // which must dominate the 5 s base slice.
        assert_eq!(
            next_catalog_slice(SLICE_BUDGET, 1907 * (1 << 20)),
            Duration::from_secs(200)
        );
        // Repeated misses never exceed the cap.
        assert_eq!(
            next_catalog_slice(CATALOG_SLICE_MAX, u64::MAX),
            CATALOG_SLICE_MAX
        );
    }

    #[test]
    fn purge_wait_preserves_schema_and_io_errors_without_retry() {
        for error in [
            PortError::SchemaIncompatible("synthetic schema failure".into()),
            PortError::SourceIo("synthetic source I/O failure".into()),
            PortError::Backend("synthetic storage failure".into()),
        ] {
            let mut error = Some(error);
            let mut calls = 0;
            let result = wait_for_next_slice_with(Instant::now() + SLICE_BUDGET, |_| {
                calls += 1;
                Err(error.take().unwrap())
            });
            assert!(!matches!(result, Ok(_) | Err(PortError::WriterBusy(_))));
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn purge_startup_wrong_root_and_unknown_schema_remain_hard_failures() {
        let fixture = Fixture::new();
        let other = agent_session_grep_testkit::tempdir().unwrap();
        assert!(matches!(
            read_before(
                fixture.root(),
                RootIdentity::read(other.path()).unwrap(),
                Instant::now() + SLICE_BUDGET
            ),
            Err(PortError::GenerationMismatch(_))
        ));
        let writer = Connection::open(SqliteControlStore::path(fixture.root())).unwrap();
        writer.pragma_update(None, "user_version", 999_i64).unwrap();
        assert!(matches!(
            open_before(fixture.root(), Instant::now() + SLICE_BUDGET),
            Err(PortError::SchemaIncompatible(_))
        ));
        fixture.assert_original();
    }
}
