//! Synthetic private SQLite connections and real cooperating child processes.
//! No provider history, host registration or real uninstall is touched.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    control::{INSTALLATION_LOCK_KEY, PURGE_LOCK_KEY},
    managed_control_lifetime::{
        ControlHandleLease, ControlRetirement, RETIREMENT_MARKER, RETIREMENT_PENDING_MARKER,
        RetiredControlFile, RetirementBinding, RetirementDrainGuards, RetirementIntent,
        validate_retirement,
    },
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, SharedGuard},
    managed_store::ManagedStore,
};
use agent_session_grep_ports::{PortError, PortResult, control::*};
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn acquire<T>(mut attempt: impl FnMut() -> PortResult<T>) -> T {
    // Fixtures own their roots, but parallel tests can briefly delay real OS or
    // SQLite acquisition. Keep setup retries typed and explicitly bounded.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match attempt() {
            Ok(value) => return value,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => std::thread::yield_now(),
            Err(error) => panic!("synthetic capability acquisition failed: {error:?}"),
        }
    }
}
fn lock(root: &Path, kind: LockKind) -> ExclusiveGuard {
    acquire(|| ExclusiveGuard::try_acquire(root, kind.clone()))
}
fn assert_busy<T>(result: PortResult<T>) {
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
}
fn assert_retired<T>(result: PortResult<T>) {
    assert!(matches!(result, Err(PortError::SchemaIncompatible(_))));
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    prefix: PathBuf,
    catalog: PathBuf,
    control: Option<SqliteControlStore>,
    installation: ExclusiveGuard,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private-data");
        let prefix = temp.path().join("immutable-install");
        fs::create_dir(&prefix).unwrap();
        let control = SqliteControlStore::create(
            &root,
            &id("synthetic-installation"),
            DesiredUpdates::Paused,
        )
        .unwrap();
        let catalog = root.join("catalog.db");
        let store =
            acquire(|| ManagedStore::create(&catalog, &control, id("synthetic-incarnation"), 1));
        let worker_lock = lock(&root, LockKind::Background);
        {
            let worker = acquire(|| control.bind_worker(&worker_lock, id("synthetic-boot")));
            let current = acquire(|| control.status()).policy.control_seq;
            acquire(|| control.register_worker(current, &worker, 1, 1));
            acquire(|| store.reconcile_progress(&control, &worker));
        }
        drop(worker_lock);
        drop(store);
        let installation = lock(
            &prefix,
            LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY).unwrap()),
        );
        {
            let policy = lock(&root, LockKind::PolicyOwner);
            let bound = acquire(|| control.bind_control_root(&policy));
            acquire(|| {
                control.record_verified_installation_prefix(
                    &prefix,
                    &installation,
                    &bound,
                    Instant::now() + Duration::from_secs(5),
                )
            });
        }
        Self {
            _temp: temp,
            root,
            prefix,
            catalog,
            control: Some(control),
            installation,
        }
    }
    fn fence(&self) {
        let control = self.control.as_ref().unwrap();
        let policy = lock(&self.root, LockKind::PolicyOwner);
        let bound = acquire(|| control.bind_control_root(&policy));
        let installation = acquire(|| control.bind_installation(&self.prefix, &self.installation));
        acquire(|| {
            control.begin_maintenance(
                acquire(|| control.status()).policy.control_seq,
                &id("synthetic-uninstall"),
                &bound,
                &installation,
                MaintenanceFence {
                    state: MaintenanceState::Uninstalling,
                    owner: Some(id("synthetic-uninstall")),
                    phase: Some(MaintenancePhase::Quiescing),
                },
            )
        });
    }
    fn close(&mut self) {
        drop(self.control.take());
    }
}
fn bind_intent<'a>(
    control: &SqliteControlStore,
    catalog: &Path,
    prefix: &Path,
    installation: &'a ExclusiveGuard,
) -> RetirementIntent<'a> {
    acquire(|| {
        RetirementIntent::bind(
            control,
            catalog,
            prefix,
            installation,
            &id("synthetic-uninstall"),
        )
    })
}

struct Drains {
    policy_owner: ExclusiveGuard,
    emission: ExclusiveGuard,
    catalog: ExclusiveGuard,
    background: ExclusiveGuard,
    supervisor: ExclusiveGuard,
    purge: ExclusiveGuard,
}
impl Drains {
    fn new(root: &Path) -> Self {
        let emission = lock(root, LockKind::PolicyEmission);
        let catalog = lock(root, LockKind::CatalogHandles);
        let background = lock(root, LockKind::Background);
        let supervisor = lock(root, LockKind::Supervisor);
        let purge = lock(
            root,
            LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY).unwrap()),
        );
        let policy_owner = lock(root, LockKind::PolicyOwner);
        Self {
            policy_owner,
            emission,
            catalog,
            background,
            supervisor,
            purge,
        }
    }
    fn proof(&self) -> RetirementDrainGuards<'_> {
        RetirementDrainGuards {
            policy_owner: &self.policy_owner,
            emission: &self.emission,
            catalog_handles: &self.catalog,
            background: &self.background,
            supervisor: &self.supervisor,
            purge: &self.purge,
        }
    }
}
fn expected<'a>(
    installation: &'a ControlId,
    incarnation: &'a ControlId,
    operation: &'a ControlId,
) -> RetirementBinding<'a> {
    RetirementBinding {
        installation,
        catalog_incarnation: incarnation,
        operation,
    }
}

#[test]
fn missing_control_has_no_root_or_lock_side_effects() {
    let empty = agent_session_grep_testkit::tempdir().unwrap();
    let missing = empty.path().join("missing");
    assert!(matches!(
        ControlHandleLease::try_acquire(&missing),
        Err(PortError::NotFound(_))
    ));
    assert!(matches!(
        ControlHandleLease::try_acquire(empty.path()),
        Err(PortError::NotFound(_))
    ));
    assert!(!missing.exists());
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
}

#[test]
fn actual_control_connections_retain_shared_lease_until_the_last_close() {
    let mut f = Fixture::new();
    let reader = SqliteControlStore::open_current_read_only(&f.root).unwrap();
    let writer = SqliteControlStore::open_current_writable(&f.root).unwrap();
    assert_busy(ExclusiveGuard::try_acquire(
        &f.root,
        LockKind::ControlHandles,
    ));
    // PolicyOwner is an independent short transaction gate, not connection drain.
    drop(lock(&f.root, LockKind::PolicyOwner));
    f.close();
    assert_busy(ExclusiveGuard::try_acquire(
        &f.root,
        LockKind::ControlHandles,
    ));
    drop(reader);
    assert_busy(ExclusiveGuard::try_acquire(
        &f.root,
        LockKind::ControlHandles,
    ));
    drop(writer);
    let exclusive = lock(&f.root, LockKind::ControlHandles);
    assert_busy(ControlHandleLease::try_acquire(&f.root));
    drop(exclusive);
    drop(acquire(|| ControlHandleLease::try_acquire(&f.root)));
}

#[test]
fn no_uninstall_fence_or_wrong_operation_cannot_bind_retirement() {
    let f = Fixture::new();
    assert!(
        RetirementIntent::bind(
            f.control.as_ref().unwrap(),
            &f.catalog,
            &f.prefix,
            &f.installation,
            &id("synthetic-uninstall")
        )
        .is_err()
    );
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
    f.fence();
    assert!(
        RetirementIntent::bind(
            f.control.as_ref().unwrap(),
            &f.catalog,
            &f.prefix,
            &f.installation,
            &id("wrong-operation")
        )
        .is_err()
    );
    assert_eq!(
        f.control
            .as_ref()
            .unwrap()
            .status()
            .unwrap()
            .desired_updates,
        DesiredUpdates::Paused
    );
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
}

#[test]
fn retirement_requires_caller_connections_closed_and_exact_drain_kinds() {
    let mut f = Fixture::new();
    f.fence();
    let intent = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    let drains = Drains::new(&f.root);
    assert_busy(intent.try_acquire(drains.proof()));
    drop(f.control.take());
    let mut wrong = drains.proof();
    wrong.supervisor = &drains.background;
    assert!(matches!(
        intent.try_acquire(wrong),
        Err(PortError::InvalidRequest(_))
    ));
    let other = agent_session_grep_testkit::tempdir().unwrap();
    let wrong_root = lock(other.path(), LockKind::Supervisor);
    let mut wrong = drains.proof();
    wrong.supervisor = &wrong_root;
    assert!(matches!(
        intent.try_acquire(wrong),
        Err(PortError::InvalidRequest(_))
    ));
    drop(acquire(|| intent.try_acquire(drains.proof())));
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
}

#[test]
fn marker_is_bound_durable_content_free_and_refuses_double_retirement() {
    let mut f = Fixture::new();
    f.fence();
    let intent = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    let root = &f.root;
    let drains = Drains::new(root);
    // Close through the disjoint field without releasing the immutable prefix lock.
    drop(f.control.take());
    let retirement = acquire(|| intent.try_acquire(drains.proof()));
    retirement.publish_marker().unwrap();
    retirement.validate_marker().unwrap();
    assert!(!root.join(RETIREMENT_PENDING_MARKER).exists());
    let bytes = fs::read(root.join(RETIREMENT_MARKER)).unwrap();
    assert!(bytes.len() <= 2048);
    assert!(!String::from_utf8_lossy(&bytes).contains(&root.display().to_string()));
    assert_retired(retirement.publish_marker());
    assert_eq!(fs::read(root.join(RETIREMENT_MARKER)).unwrap(), bytes);
    drop(retirement);
    assert_retired(ControlHandleLease::try_acquire(root));
    assert_retired(ControlHandleLease::try_acquire_for_create(root));
    assert_retired(SqliteControlStore::open_current_read_only(root));
}

#[test]
fn marker_corruption_wrong_binding_and_removed_control_never_regrant_admission() {
    let mut f = Fixture::new();
    f.fence();
    let intent = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    let drains = Drains::new(&f.root);
    drop(f.control.take());
    let retirement = acquire(|| intent.try_acquire(drains.proof()));
    retirement.publish_marker().unwrap();
    drop(retirement);
    let marker_path = f.root.join(RETIREMENT_MARKER);
    let original = fs::read(&marker_path).unwrap();
    let installation = id("synthetic-installation");
    let incarnation = id("synthetic-incarnation");
    let operation = id("synthetic-uninstall");
    assert!(
        ControlRetirement::try_resume(
            &f.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &incarnation, &id("wrong-operation")),
            drains.proof()
        )
        .is_err()
    );
    for bad in [Vec::new(), b"{broken marker".to_vec(), vec![b'x'; 2049]] {
        fs::write(&marker_path, &bad).unwrap();
        assert!(
            ControlRetirement::try_resume(
                &f.root,
                &f.prefix,
                &f.installation,
                expected(&installation, &incarnation, &operation),
                drains.proof()
            )
            .is_err()
        );
        assert_retired(ControlHandleLease::try_acquire(&f.root));
        assert_eq!(fs::read(&marker_path).unwrap(), bad);
    }
    fs::write(&marker_path, &original).unwrap();
    let remover = acquire(|| {
        ControlRetirement::try_resume(
            &f.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &incarnation, &operation),
            drains.proof(),
        )
    });
    assert!(
        remover
            .remove_control_file(RetiredControlFile::Database)
            .unwrap()
    );
    assert!(
        !remover
            .remove_control_file(RetiredControlFile::Database)
            .unwrap()
    );
    remover.validate_marker().unwrap();
    drop(remover);
    assert_retired(SqliteControlStore::open_current_writable(&f.root));
    let resumed = acquire(|| {
        ControlRetirement::try_resume(
            &f.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &incarnation, &operation),
            drains.proof(),
        )
    });
    resumed.validate_marker().unwrap();
    assert!(!SqliteControlStore::path(&f.root).exists());
    drop(resumed);
    let mut other = Fixture::new();
    other.close();
    fs::write(other.root.join(RETIREMENT_MARKER), &original).unwrap();
    let other_drains = Drains::new(&other.root);
    assert!(
        ControlRetirement::try_resume(
            &other.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &incarnation, &operation),
            other_drains.proof()
        )
        .is_err()
    );
    assert_retired(validate_retirement(&other.root));
}

#[test]
fn pending_or_non_file_marker_refuses_normal_admission_even_without_database() {
    let f = Fixture::new();
    fs::write(f.root.join(RETIREMENT_PENDING_MARKER), b"partial").unwrap();
    assert_retired(f.control.as_ref().unwrap().status());
    assert_retired(ControlHandleLease::try_acquire(&f.root));
    fs::remove_file(f.root.join(RETIREMENT_PENDING_MARKER)).unwrap();
    fs::create_dir(f.root.join(RETIREMENT_MARKER)).unwrap();
    assert_retired(validate_retirement(&f.root));
}

#[test]
fn complete_pending_marker_resumes_only_under_matching_binding() {
    let mut f = Fixture::new();
    f.fence();
    let intent = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    let drains = Drains::new(&f.root);
    drop(f.control.take());
    let retirement = acquire(|| intent.try_acquire(drains.proof()));
    retirement.publish_marker().unwrap();
    drop(retirement);
    fs::rename(
        f.root.join(RETIREMENT_MARKER),
        f.root.join(RETIREMENT_PENDING_MARKER),
    )
    .unwrap();
    assert_retired(validate_retirement(&f.root));
    let installation = id("synthetic-installation");
    let incarnation = id("synthetic-incarnation");
    let operation = id("synthetic-uninstall");
    assert!(
        ControlRetirement::try_resume(
            &f.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &id("wrong-incarnation"), &operation),
            drains.proof()
        )
        .is_err()
    );
    assert!(f.root.join(RETIREMENT_PENDING_MARKER).is_file());
    let resumed = acquire(|| {
        ControlRetirement::try_resume(
            &f.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &incarnation, &operation),
            drains.proof(),
        )
    });
    resumed.validate_marker().unwrap();
    assert!(!f.root.join(RETIREMENT_PENDING_MARKER).exists());
    assert!(f.root.join(RETIREMENT_MARKER).is_file());
}

#[test]
fn retirement_refresh_tracks_real_control_mutation_before_final_close() {
    let mut f = Fixture::new();
    f.fence();
    let original = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    let drains = Drains::new(&f.root);
    let control = f.control.as_ref().unwrap();
    let previous = control.status().unwrap().policy.control_seq;
    control
        .set_desired_updates(previous, DesiredUpdates::Stopped)
        .unwrap();
    assert!(control.status().unwrap().policy.control_seq > previous);
    let refreshed = original.refresh(control, &drains.policy_owner).unwrap();
    drop(f.control.take());
    assert!(matches!(
        original.try_acquire(drains.proof()),
        Err(PortError::GenerationMismatch(_))
    ));
    let retirement = acquire(|| refreshed.try_acquire(drains.proof()));
    retirement.publish_marker().unwrap();
    retirement.validate_marker().unwrap();
}

#[test]
fn marker_hard_link_alias_never_becomes_retirement_authority() {
    let mut f = Fixture::new();
    f.fence();
    let intent = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    let drains = Drains::new(&f.root);
    drop(f.control.take());
    let retirement = acquire(|| intent.try_acquire(drains.proof()));
    retirement.publish_marker().unwrap();
    drop(retirement);
    fs::hard_link(
        f.root.join(RETIREMENT_MARKER),
        f.root.join("synthetic-marker-alias"),
    )
    .unwrap();
    let installation = id("synthetic-installation");
    let incarnation = id("synthetic-incarnation");
    let operation = id("synthetic-uninstall");
    assert!(
        ControlRetirement::try_resume(
            &f.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &incarnation, &operation),
            drains.proof()
        )
        .is_err()
    );
    assert_retired(validate_retirement(&f.root));
}

#[cfg(unix)]
#[test]
fn replaced_root_and_marker_symlink_are_rejected_with_no_target_content_access() {
    use std::os::unix::fs::symlink;
    let mut f = Fixture::new();
    f.fence();
    let intent = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    drop(f.control.take());
    let moved = f._temp.path().join("retained-private-data");
    fs::rename(&f.root, &moved).unwrap();
    fs::create_dir(&f.root).unwrap();
    let drains = Drains::new(&f.root);
    assert!(intent.try_acquire(drains.proof()).is_err());
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
    let target = f._temp.path().join("nonexistent-synthetic-target");
    symlink(&target, f.root.join(RETIREMENT_MARKER)).unwrap();
    assert_retired(validate_retirement(&f.root));
    assert!(!target.exists());
}

#[cfg(windows)]
#[test]
fn retirement_marker_junction_is_rejected_without_following_target() {
    let f = Fixture::new();
    let target = f._temp.path().join("synthetic-target");
    fs::create_dir(&target).unwrap();
    let marker = f.root.join(RETIREMENT_MARKER);
    let output = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&marker)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "synthetic junction creation failed"
    );
    assert_retired(validate_retirement(&f.root));
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
}

#[test]
fn terminal_control_file_removal_rejects_unowned_aliases_and_preserves_locks() {
    let mut f = Fixture::new();
    f.fence();
    let intent = bind_intent(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
    );
    let drains = Drains::new(&f.root);
    drop(f.control.take());
    let retirement = acquire(|| intent.try_acquire(drains.proof()));
    retirement.publish_marker().unwrap();
    let alias = f.root.join("synthetic-control-alias");
    fs::hard_link(SqliteControlStore::path(&f.root), &alias).unwrap();
    assert!(
        retirement
            .remove_control_file(RetiredControlFile::Database)
            .is_err()
    );
    assert!(SqliteControlStore::path(&f.root).is_file());
    fs::remove_file(&alias).unwrap();
    // Do not follow a directory in place of an owned sidecar.
    let wal = f.root.join("control.db-wal");
    // Read-only WAL validation may retain its owned sidecar. Remove it through
    // the actual terminal capability before testing an invalid directory leaf.
    let _ = retirement
        .remove_control_file(RetiredControlFile::Wal)
        .unwrap();
    assert!(!wal.exists());
    fs::create_dir(&wal).unwrap();
    assert!(
        retirement
            .remove_control_file(RetiredControlFile::Wal)
            .is_err()
    );
    fs::remove_dir(&wal).unwrap();
    assert!(
        retirement
            .remove_control_file(RetiredControlFile::Database)
            .unwrap()
    );
    assert!(
        !retirement
            .remove_control_file(RetiredControlFile::Wal)
            .unwrap()
    );
    let _ = retirement
        .remove_control_file(RetiredControlFile::SharedMemory)
        .unwrap();
    retirement.validate_marker().unwrap();
    for name in [
        RETIREMENT_MARKER,
        "control-handles.lock",
        "control-create.lock",
        "catalog-handles.lock",
        "policy-owner.lock",
        "background.lock",
    ] {
        assert!(f.root.join(name).is_file());
    }
}

#[test]
fn expired_deadline_bind_refresh_and_acquire_preserve_control_and_no_marker() {
    let mut f = Fixture::new();
    f.fence();
    let control = f.control.as_ref().unwrap();
    let original = control.status().unwrap();
    assert_busy(RetirementIntent::bind_with_deadline(
        control,
        &f.catalog,
        &f.prefix,
        &f.installation,
        &id("synthetic-uninstall"),
        Instant::now(),
    ));
    let intent = RetirementIntent::bind_with_deadline(
        control,
        &f.catalog,
        &f.prefix,
        &f.installation,
        &id("synthetic-uninstall"),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let drains = Drains::new(&f.root);
    assert_busy(intent.refresh_with_deadline(control, &drains.policy_owner, Instant::now()));
    assert_eq!(control.status().unwrap(), original);
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
    assert!(!f.root.join(RETIREMENT_PENDING_MARKER).exists());
    assert_busy(
        intent.try_acquire_with_deadline(drains.proof(), Instant::now() + Duration::from_secs(1)),
    );
    drop(f.control.take());
    assert_busy(intent.try_acquire_with_deadline(drains.proof(), Instant::now()));
    let retirement = intent
        .try_acquire_with_deadline(drains.proof(), Instant::now() + Duration::from_secs(30))
        .unwrap();
    retirement
        .publish_marker_with_deadline(Instant::now() + Duration::from_secs(30))
        .unwrap();
}

#[test]
fn expired_before_marker_or_cleanup_preserves_real_drain_and_control_bytes() {
    let mut f = Fixture::new();
    f.fence();
    let intent = RetirementIntent::bind_with_deadline(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
        &id("synthetic-uninstall"),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let drains = Drains::new(&f.root);
    drop(f.control.take());
    let retirement = intent
        .try_acquire_with_deadline(drains.proof(), Instant::now() + Duration::from_secs(30))
        .unwrap();
    let original = fs::read(SqliteControlStore::path(&f.root)).unwrap();
    assert_busy(retirement.publish_marker_with_deadline(Instant::now()));
    assert_eq!(
        fs::read(SqliteControlStore::path(&f.root)).unwrap(),
        original
    );
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
    assert!(!f.root.join(RETIREMENT_PENDING_MARKER).exists());
    assert_busy(ExclusiveGuard::try_acquire(
        &f.root,
        LockKind::ControlHandles,
    ));
    retirement
        .publish_marker_with_deadline(Instant::now() + Duration::from_secs(30))
        .unwrap();
    let marker = fs::read(f.root.join(RETIREMENT_MARKER)).unwrap();
    assert_busy(retirement.validate_marker_with_deadline(Instant::now()));
    assert_busy(
        retirement.remove_control_file_with_deadline(RetiredControlFile::Database, Instant::now()),
    );
    assert_eq!(
        fs::read(SqliteControlStore::path(&f.root)).unwrap(),
        original
    );
    assert_eq!(fs::read(f.root.join(RETIREMENT_MARKER)).unwrap(), marker);
    // Marker existence refuses normal admission before the shared lease is
    // attempted, even while the terminal capability still owns its drain.
    assert_retired(ControlHandleLease::try_acquire(&f.root));
    retirement
        .validate_marker_with_deadline(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert!(
        retirement
            .remove_control_file_with_deadline(
                RetiredControlFile::Database,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap()
    );
    assert_eq!(fs::read(f.root.join(RETIREMENT_MARKER)).unwrap(), marker);
    assert_retired(ControlHandleLease::try_acquire(&f.root));
}

#[test]
fn expired_resume_preserves_pending_marker_and_matching_deadline_recovery() {
    let mut f = Fixture::new();
    f.fence();
    let intent = RetirementIntent::bind_with_deadline(
        f.control.as_ref().unwrap(),
        &f.catalog,
        &f.prefix,
        &f.installation,
        &id("synthetic-uninstall"),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let drains = Drains::new(&f.root);
    drop(f.control.take());
    let retirement = intent
        .try_acquire_with_deadline(drains.proof(), Instant::now() + Duration::from_secs(30))
        .unwrap();
    retirement
        .publish_marker_with_deadline(Instant::now() + Duration::from_secs(30))
        .unwrap();
    drop(retirement);
    // Leaf rename is contained in this one synthetic fixture; neither moves a
    // directory nor alters real provider source or personal control state.
    fs::rename(
        f.root.join(RETIREMENT_MARKER),
        f.root.join(RETIREMENT_PENDING_MARKER),
    )
    .unwrap();
    let pending = fs::read(f.root.join(RETIREMENT_PENDING_MARKER)).unwrap();
    let installation = id("synthetic-installation");
    let incarnation = id("synthetic-incarnation");
    let operation = id("synthetic-uninstall");
    assert_busy(ControlRetirement::try_resume_with_deadline(
        &f.root,
        &f.prefix,
        &f.installation,
        expected(&installation, &incarnation, &operation),
        drains.proof(),
        Instant::now(),
    ));
    assert_eq!(
        fs::read(f.root.join(RETIREMENT_PENDING_MARKER)).unwrap(),
        pending
    );
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
    assert_retired(ControlHandleLease::try_acquire(&f.root));
    assert!(
        ControlRetirement::try_resume_with_deadline(
            &f.root,
            &f.prefix,
            &f.installation,
            expected(&installation, &id("wrong-incarnation"), &operation),
            drains.proof(),
            Instant::now() + Duration::from_secs(1),
        )
        .is_err()
    );
    assert_eq!(
        fs::read(f.root.join(RETIREMENT_PENDING_MARKER)).unwrap(),
        pending
    );
    let resumed = ControlRetirement::try_resume_with_deadline(
        &f.root,
        &f.prefix,
        &f.installation,
        expected(&installation, &incarnation, &operation),
        drains.proof(),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    resumed
        .validate_marker_with_deadline(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert!(!f.root.join(RETIREMENT_PENDING_MARKER).exists());
    assert_eq!(fs::read(f.root.join(RETIREMENT_MARKER)).unwrap(), pending);
}

const CHILD_MODE: &str = "ASG_CONTROL_LIFETIME_SYNTHETIC_CHILD";
const CHILD_ROOT: &str = "ASG_CONTROL_LIFETIME_SYNTHETIC_ROOT";
#[test]
fn control_lifetime_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap());
    let reader =
        (mode == "reader").then(|| SqliteControlStore::open_current_read_only(&root).unwrap());
    let exclusive = (mode == "exclusive").then(|| lock(&root, LockKind::ControlHandles));
    println!("control-lifetime-ready");
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    if line.trim() == "crash" {
        std::process::exit(23);
    }
    drop(reader);
    drop(exclusive);
}
struct ChildHolder {
    child: Child,
    output: BufReader<std::process::ChildStdout>,
}
impl ChildHolder {
    fn start(root: &Path, mode: &str) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "control_lifetime_child", "--nocapture"])
            .env(CHILD_MODE, mode)
            .env(CHILD_ROOT, root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.trim() == "control-lifetime-ready" {
                break;
            }
        }
        Self { child, output }
    }
    fn finish(mut self, request: &str, code: i32) {
        writeln!(self.child.stdin.take().unwrap(), "{request}").unwrap();
        io::copy(&mut self.output, &mut io::sink()).unwrap();
        assert_eq!(self.child.wait().unwrap().code(), Some(code));
    }
}
impl Drop for ChildHolder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn other_process_control_connection_and_exclusive_guard_prove_real_drain() {
    let mut f = Fixture::new();
    f.close();
    let child = ChildHolder::start(&f.root, "reader");
    let local = acquire(|| SharedGuard::try_acquire(&f.root, LockKind::ControlHandles));
    assert_busy(ExclusiveGuard::try_acquire(
        &f.root,
        LockKind::ControlHandles,
    ));
    child.finish("release", 0);
    assert_busy(ExclusiveGuard::try_acquire(
        &f.root,
        LockKind::ControlHandles,
    ));
    drop(local);
    let child = ChildHolder::start(&f.root, "exclusive");
    assert_busy(ControlHandleLease::try_acquire(&f.root));
    child.finish("crash", 23);
    drop(lock(&f.root, LockKind::ControlHandles));
}

#[test]
fn terminal_validation_uses_current_schema_and_exact_runtime_index_allowlist() {
    use agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION;
    use rusqlite::Connection;

    for sql in [
        "PRAGMA user_version=1; UPDATE control_meta SET schema_version=1;
            DROP INDEX cycles_runtime_state; DROP INDEX barriers_runtime_state; DROP INDEX barriers_runtime_admission;",
        "DROP INDEX cycles_runtime_state;",
        "CREATE INDEX unowned_runtime_index ON cycles(policy_epoch);",
        "PRAGMA user_version=3; UPDATE control_meta SET schema_version=3;",
    ] {
        let mut f = Fixture::new();
        f.fence();
        let intent = bind_intent(
            f.control.as_ref().unwrap(),
            &f.catalog,
            &f.prefix,
            &f.installation,
        );
        let drains = Drains::new(&f.root);
        drop(f.control.take());
        let conn = Connection::open(SqliteControlStore::path(&f.root)).unwrap();
        assert_eq!(conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)).unwrap(), CONTROL_SCHEMA_VERSION);
        conn.execute_batch(sql).unwrap();
        drop(conn);
        assert_retired(intent.try_acquire(drains.proof()));
        assert!(!f.root.join(RETIREMENT_MARKER).exists());
        assert!(!f.root.join(RETIREMENT_PENDING_MARKER).exists());
        assert!(SqliteControlStore::path(&f.root).exists());
    }
}
