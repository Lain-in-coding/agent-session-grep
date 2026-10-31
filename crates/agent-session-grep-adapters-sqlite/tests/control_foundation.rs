use agent_session_grep_adapters_sqlite::SqliteControlStore;
use agent_session_grep_adapters_sqlite::managed_locks::{
    ExclusiveGuard, LockKind, RootIdentity, SharedGuard,
};
use agent_session_grep_ports::{PortError, SearchProvider, control::*};
use rusqlite::Connection;
use std::path::Path;

fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn zero() -> ControlSeq {
    ControlSeq::new(0).unwrap()
}
fn locator(relative: &str) -> CanonicalLocator {
    #[cfg(windows)]
    let absolute = format!(r"C:\synthetic\{}", relative.replace('/', "\\"));
    #[cfg(not(windows))]
    let absolute = format!("/synthetic/{relative}");
    CanonicalLocator::parse(&absolute).unwrap()
}
fn region(provider: SearchProvider, relative: &str, kind: RootKind) -> ScopeRegion {
    ScopeRegion {
        provider,
        locator: locator(relative),
        kind,
    }
}
fn request(provider: SearchProvider, relative: &str, kind: RootKind) -> SelectionRequest {
    SelectionRequest {
        region: region(provider, relative, kind),
        root_identity: Some(id("root_identity")),
        now_ms: 10,
    }
}
fn setup() -> (tempfile::TempDir, std::path::PathBuf, SqliteControlStore) {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let store = loop {
        match SqliteControlStore::create(&root, &id("installation"), DesiredUpdates::Running) {
            Ok(store) => break store,
            Err(PortError::WriterBusy(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(error) => panic!("expected noncontended control setup: {error:?}"),
        }
    };
    (temp, root, store)
}
fn allowed(policy: &ReadPolicy, provider: SearchProvider, relative: &str) -> bool {
    policy.allows_source(provider, &locator(relative), &id("source_f"))
}
fn raw(root: &Path) -> Connection {
    Connection::open(SqliteControlStore::path(root)).unwrap()
}
fn exclusive_guard(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => panic!("expected noncontended managed lock: {error:?}"),
        }
    }
}
fn shared_guard(root: &Path, kind: LockKind) -> SharedGuard {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match SharedGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => panic!("expected noncontended managed lock: {error:?}"),
        }
    }
}
fn retry_expected_success<T>(
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    // These expected-success tests own independent roots. Parallel tests can
    // briefly starve the production 250ms runtime check, so retry only typed
    // contention inside one explicit bound. Failure-path assertions below stay
    // unbounded and continue to require their original Busy result.
    let end = std::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        match operation() {
            Err(PortError::WriterBusy(_)) if std::time::Instant::now() < end => {
                std::thread::yield_now();
            }
            result => return result,
        }
    }
}

#[test]
fn read_open_missing_creates_nothing() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let absent = temp.path().join("absent");
    assert!(matches!(
        SqliteControlStore::open_read_only(&absent, &id("installation")),
        Err(PortError::NotFound(_))
    ));
    assert!(!absent.exists());
    assert!(matches!(
        SqliteControlStore::open_existing_writable(&absent, &id("installation")),
        Err(PortError::NotFound(_))
    ));
    for result in [
        SqliteControlStore::open_current_read_only(&absent),
        SqliteControlStore::open_current_writable(&absent),
        SqliteControlStore::open_current_read_only(temp.path()),
        SqliteControlStore::open_current_writable(temp.path()),
    ] {
        assert!(matches!(result, Err(PortError::NotFound(_))));
    }
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn current_open_discovers_identity_without_resetting_policy_or_granting_writes() {
    let (_temp, root, store) = setup();
    let selected = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let denied = store
        .revoke_selection(selected.control_seq, &selected.value.id, None, 20)
        .unwrap();
    store
        .set_desired_updates(denied.control_seq, DesiredUpdates::Paused)
        .unwrap();
    let before = control_rows(&root);
    let read = SqliteControlStore::open_current_read_only(&root).unwrap();
    let write = SqliteControlStore::open_current_writable(&root).unwrap();
    assert_eq!(read.status().unwrap(), store.status().unwrap());
    assert_eq!(write.status().unwrap(), read.status().unwrap());
    assert_eq!(
        read.status().unwrap().policy.installation_id,
        id("installation")
    );
    assert!(matches!(
        read.set_desired_updates(current(&read), DesiredUpdates::Running),
        Err(PortError::InvalidRequest(_))
    ));
    assert!(SqliteControlStore::open_read_only(&root, &id("different-installation")).is_err());
    assert!(
        SqliteControlStore::open_existing_writable(&root, &id("different-installation")).is_err()
    );
    assert!(control_rows(&root) == before);
    retry_expected_success(|| write.set_desired_updates(current(&write), DesiredUpdates::Running))
        .unwrap();
    let after = read.status().unwrap();
    assert_eq!(after.desired_updates, DesiredUpdates::Running);
    assert!(after.policy.emission_blocked());
    assert!(!allowed(&after.policy, SearchProvider::Claude, "R/F"));
    assert_eq!(write.purge_jobs().unwrap(), store.purge_jobs().unwrap());
}

#[test]
fn lifecycle_status_matches_full_status_through_policy_and_maintenance_changes() {
    let (_temp, root, store) = setup();
    let read = SqliteControlStore::open_current_read_only(&root).unwrap();
    let observe = || {
        store
            .with_runtime_deadline(
                std::time::Instant::now() + std::time::Duration::from_secs(8),
                || {
                    let before = control_rows(&root);
                    let status = store.status()?;
                    assert_eq!(store.lifecycle_status()?, status);
                    assert_eq!(read.lifecycle_status()?, status);
                    assert!(control_rows(&root) == before);
                    Ok(status)
                },
            )
            .unwrap()
    };
    let initial = observe();
    let selected = retry_expected_success(|| {
        store.add_selection(
            initial.policy.control_seq,
            request(SearchProvider::Claude, "R", RootKind::Root),
        )
    })
    .unwrap();
    let enabled = observe();
    assert!(allowed(&enabled.policy, SearchProvider::Claude, "R/F"));
    assert_eq!(enabled.policy.selections, vec![selected.value.clone()]);

    let paused = retry_expected_success(|| {
        store.set_desired_updates(enabled.policy.control_seq, DesiredUpdates::Paused)
    })
    .unwrap();
    let paused_status = observe();
    assert_eq!(paused_status.desired_updates, DesiredUpdates::Paused);
    assert_eq!(
        paused_status.policy.policy_epoch,
        enabled.policy.policy_epoch
    );
    assert!(allowed(
        &paused_status.policy,
        SearchProvider::Claude,
        "R/F"
    ));

    let owner = id("lifecycle_owner");
    let fence = MaintenanceFence {
        state: MaintenanceState::Updating,
        owner: Some(owner.clone()),
        phase: Some(MaintenancePhase::Quiescing),
    };
    let fenced =
        retry_expected_success(|| store.set_maintenance(paused.control_seq, &owner, fence.clone()))
            .unwrap();
    let fenced_status = observe();
    assert_eq!(fenced_status.policy.maintenance, fence);
    assert_eq!(fenced_status.desired_updates, DesiredUpdates::Paused);
    assert!(fenced_status.policy.emission_blocked());

    let revoked = retry_expected_success(|| {
        store.revoke_selection(fenced.control_seq, &selected.value.id, None, 20)
    })
    .unwrap();
    let denied = observe();
    assert!(!allowed(&denied.policy, SearchProvider::Claude, "R/F"));
    assert_eq!(denied.policy.revocations.len(), 1);
    assert_eq!(
        denied.policy.revocations[0].state,
        RevocationState::AwaitingDrain
    );
    assert_eq!(denied.policy.exclusions.len(), 1);
    assert_eq!(store.purge_jobs().unwrap()[0].state, PurgeState::Pending);

    retry_expected_success(|| {
        store.set_maintenance(revoked.control_seq, &owner, MaintenanceFence::idle())
    })
    .unwrap();
    let idle = observe();
    assert_eq!(idle.policy.maintenance, MaintenanceFence::idle());
    assert_eq!(idle.desired_updates, DesiredUpdates::Paused);
    assert!(!allowed(&idle.policy, SearchProvider::Claude, "R/F"));
    assert!(idle.policy.emission_blocked());
}

#[test]
fn lifecycle_status_expired_nested_end_preserves_control_and_restores_outer_scope() {
    use std::time::{Duration, Instant};

    let (_temp, root, store) = setup();
    let selected = retry_expected_success(|| {
        store.add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
    })
    .unwrap();
    retry_expected_success(|| {
        store.set_desired_updates(selected.control_seq, DesiredUpdates::Paused)
    })
    .unwrap();
    let before = control_rows(&root);
    let outer_end = Instant::now() + Duration::from_secs(8);
    store
        .with_runtime_deadline(outer_end, || {
            let expired = Instant::now();
            let result = store.with_runtime_deadline(expired, || store.lifecycle_status());
            assert!(matches!(result, Err(PortError::WriterBusy(_))));
            let inner_end = Instant::now() + Duration::from_millis(40);
            let result = store.with_runtime_deadline(inner_end, || {
                while Instant::now() < inner_end {
                    std::thread::sleep(
                        Duration::from_millis(1)
                            .min(inner_end.saturating_duration_since(Instant::now())),
                    );
                }
                // Inspect the method's result before the wrapper's trailing tick.
                let result = store.lifecycle_status();
                assert!(matches!(&result, Err(PortError::WriterBusy(_))));
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(outer_end),
                    inner_end
                );
                result
            });
            assert!(matches!(result, Err(PortError::WriterBusy(_))));
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(outer_end + Duration::from_secs(1)),
                outer_end
            );

            let result = store.with_runtime_deadline(outer_end + Duration::from_secs(1), || {
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(
                        outer_end + Duration::from_secs(2)
                    ),
                    outer_end
                );
                store.lifecycle_status()
            })?;
            assert_eq!(result.desired_updates, DesiredUpdates::Paused);
            Ok(())
        })
        .unwrap();
    assert!(control_rows(&root) == before);
    let later_end = Instant::now() + Duration::from_secs(10);
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(later_end),
        later_end
    );
}

#[test]
fn lifecycle_status_rejects_retired_root_without_creating_or_changing_state() {
    use agent_session_grep_adapters_sqlite::managed_control_lifetime::RETIREMENT_MARKER;

    let (_temp, root, store) = setup();
    let before = control_rows(&root);
    // Marker presence is authoritative denial, even when its bytes are corrupt.
    let marker = root.join(RETIREMENT_MARKER);
    std::fs::write(&marker, b"synthetic-invalid-marker").unwrap();
    let names = || {
        let mut names = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let before_names = names();
    assert!(matches!(
        store.lifecycle_status(),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert!(control_rows(&root) == before);
    assert_eq!(names(), before_names);
    assert_eq!(std::fs::read(marker).unwrap(), b"synthetic-invalid-marker");
}

#[cfg(unix)]
#[test]
fn lifecycle_status_rejects_changed_private_root_permissions_without_repair() {
    use std::os::unix::fs::PermissionsExt;

    let (_temp, root, store) = setup();
    let before = control_rows(&root);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store.lifecycle_status().is_err());
    assert!(control_rows(&root) == before);
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn fresh_schema_has_all_normative_tables_and_roundtrips() {
    let (_temp, root, store) = setup();
    let status = store.status().unwrap();
    assert_eq!(status.policy.control_seq, zero());
    assert_eq!(status.policy.policy_epoch.get(), 0);
    assert_eq!(status.desired_updates, DesiredUpdates::Running);
    assert!(!allowed(&status.policy, SearchProvider::Claude, "R/F"));
    let conn = raw(&root);
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        tables,
        vec![
            "artifact_sources",
            "backup_manifests",
            "backup_sources",
            "barrier_selections",
            "barriers",
            "control_meta",
            "cycle_selections",
            "cycles",
            "exclusions",
            "private_artifacts",
            "purge_jobs",
            "revocation_intents",
            "selections",
            "source_updates",
            "update_receipts",
            "worker_state"
        ]
    );
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    drop(stmt);
    drop(conn);
    drop(store);
    let read = SqliteControlStore::open_read_only(&root, &id("installation")).unwrap();
    assert_eq!(read.status().unwrap(), status);
    assert!(
        read.set_desired_updates(zero(), DesiredUpdates::Paused)
            .is_err()
    );
    assert!(SqliteControlStore::open_read_only(&root, &id("other_installation")).is_err());
    assert!(
        SqliteControlStore::create(&root, &id("installation"), DesiredUpdates::Stopped).is_err()
    );
    assert_eq!(read.status().unwrap(), status);
    assert!(!root.join("control.db.creating").exists());
    assert!(!root.join("control.db.creating-wal").exists());
    assert!(!root.join("control.db.creating-shm").exists());
    assert!(!root.join("control.db.creating-journal").exists());
}

#[test]
fn occupied_final_name_and_sidecars_are_never_replaced_by_creation() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
    }
    #[cfg(windows)]
    std::fs::create_dir(&root).unwrap();
    let path = SqliteControlStore::path(&root);
    std::fs::write(&path, b"occupied").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut wal_name = path.as_os_str().to_os_string();
    wal_name.push("-wal");
    let wal = std::path::PathBuf::from(wal_name);
    std::fs::write(&wal, b"sidecar").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(
        SqliteControlStore::create(&root, &id("installation"), DesiredUpdates::Running).is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), b"occupied");
    assert_eq!(std::fs::read(wal).unwrap(), b"sidecar");
}

#[test]
fn exact_revoke_wins_over_parent_and_other_provider_remains_allowed() {
    let (_temp, root, store) = setup();
    let r = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let f = store
        .add_selection(
            r.control_seq,
            request(SearchProvider::Claude, "R/F", RootKind::Exact),
        )
        .unwrap();
    let codex = store
        .add_selection(
            f.control_seq,
            request(SearchProvider::Codex, "R", RootKind::Root),
        )
        .unwrap();
    let revoked = store
        .revoke_selection(codex.control_seq, &f.value.id, Some(&id("source_f")), 20)
        .unwrap();
    assert_eq!(revoked.value.intent.state, RevocationState::AwaitingDrain);
    assert_eq!(revoked.value.purge_job.state, PurgeState::Pending);
    assert_eq!(revoked.value.intent.settled_at_ms, None);
    let policy = store.read_policy(RequestIntersection::Selected).unwrap();
    assert!(policy.emission_blocked());
    assert!(
        policy
            .selections
            .iter()
            .find(|s| s.id == r.value.id)
            .unwrap()
            .enabled
    );
    assert!(!allowed(&policy, SearchProvider::Claude, "R/F"));
    assert!(policy.allows_source(
        SearchProvider::Claude,
        &locator("R/other"),
        &id("other_source")
    ));
    assert!(allowed(&policy, SearchProvider::Codex, "R/F"));
    assert!(!allowed(&policy, SearchProvider::Claude, "R2/F"));
    // Stable identity prevents an otherwise permitted alias from resurrection.
    assert!(!allowed(&policy, SearchProvider::Claude, "R/renamed"));
    let again = store
        .revoke_selection(revoked.control_seq, &f.value.id, Some(&id("source_f")), 21)
        .unwrap();
    assert!(!again.changed);
    assert_eq!(again.value, revoked.value);
    assert_eq!(again.control_seq, revoked.control_seq);
    assert_eq!(store.purge_jobs().unwrap().len(), 1);
    // Adding the exact selection again never removes either named exclusion.
    let added = store
        .add_selection(
            again.control_seq,
            request(SearchProvider::Claude, "R/F", RootKind::Exact),
        )
        .unwrap();
    assert_eq!(added.value.id, f.value.id);
    assert!(!allowed(
        &store.status().unwrap().policy,
        SearchProvider::Claude,
        "R/F"
    ));
    drop(store);
    let reopened = SqliteControlStore::open_read_only(&root, &id("installation")).unwrap();
    assert!(!allowed(
        &reopened.status().unwrap().policy,
        SearchProvider::Claude,
        "R/F"
    ));
}

#[test]
fn named_reallow_and_request_intersection_do_not_widen_policy() {
    let (_temp, _root, store) = setup();
    let parent = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let nested = store
        .add_selection(
            parent.control_seq,
            request(SearchProvider::Claude, "R/sub", RootKind::Root),
        )
        .unwrap();
    let exact = store
        .add_selection(
            nested.control_seq,
            request(SearchProvider::Claude, "R/sub/F", RootKind::Exact),
        )
        .unwrap();
    let revoke = store
        .revoke_selection(exact.control_seq, &nested.value.id, None, 30)
        .unwrap();
    assert!(!allowed(
        &store.status().unwrap().policy,
        SearchProvider::Claude,
        "R/sub/F"
    ));
    let exclusions = store.status().unwrap().policy.exclusions;
    assert_eq!(exclusions.len(), 1);
    let removed = store
        .remove_exclusion(revoke.control_seq, &exclusions[0].id)
        .unwrap();
    assert_eq!(removed.value, exclusions[0]);
    assert!(removed.changed);
    let restricted = store
        .read_policy(RequestIntersection::Only(vec![region(
            SearchProvider::Claude,
            "R/sub/F",
            RootKind::Exact,
        )]))
        .unwrap();
    assert!(allowed(&restricted, SearchProvider::Claude, "R/sub/F"));
    assert!(!allowed(&restricted, SearchProvider::Claude, "R/other"));
    assert!(!allowed(&restricted, SearchProvider::Codex, "R/sub/F"));
    let empty = store
        .read_policy(RequestIntersection::Only(vec![]))
        .unwrap();
    assert!(!allowed(&empty, SearchProvider::Claude, "R/sub/F"));
    assert!(
        store
            .remove_exclusion(removed.control_seq, &exclusions[0].id)
            .is_err()
    );
}

#[test]
fn pause_stop_restart_persist_and_maintenance_preserves_pause_and_revoke() {
    let (_temp, root, store) = setup();
    let selection = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let paused = store
        .set_desired_updates(selection.control_seq, DesiredUpdates::Paused)
        .unwrap();
    assert_eq!(paused.policy_epoch, selection.policy_epoch);
    assert!(allowed(
        &store.status().unwrap().policy,
        SearchProvider::Claude,
        "R/F"
    ));
    let owner = id("owner");
    let fence = MaintenanceFence {
        state: MaintenanceState::Updating,
        owner: Some(owner.clone()),
        phase: Some(MaintenancePhase::Quiescing),
    };
    let started = store
        .set_maintenance(paused.control_seq, &owner, fence.clone())
        .unwrap();
    let revoked = store
        .revoke_selection(started.control_seq, &selection.value.id, None, 40)
        .unwrap();
    assert!(matches!(
        store.set_maintenance(started.control_seq, &owner, MaintenanceFence::idle()),
        Err(PortError::GenerationMismatch(_))
    ));
    assert!(
        store
            .set_maintenance(
                revoked.control_seq,
                &id("other_owner"),
                MaintenanceFence::idle()
            )
            .is_err()
    );
    let cleared = store
        .set_maintenance(revoked.control_seq, &owner, MaintenanceFence::idle())
        .unwrap();
    let status = store.status().unwrap();
    assert_eq!(status.desired_updates, DesiredUpdates::Paused);
    assert!(!allowed(&status.policy, SearchProvider::Claude, "R/F"));
    assert_eq!(status.policy.revocations.len(), 1);
    drop(store);
    let store = SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
    assert_eq!(store.status().unwrap(), status);
    let stopped = store
        .set_desired_updates(cleared.control_seq, DesiredUpdates::Stopped)
        .unwrap();
    drop(store);
    let store = SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
    assert_eq!(
        store.status().unwrap().desired_updates,
        DesiredUpdates::Stopped
    );
    let resumed = retry_expected_success(|| {
        store.set_desired_updates(stopped.control_seq, DesiredUpdates::Running)
    })
    .unwrap();
    assert_eq!(store.status().unwrap().restart_request_seq.get(), 1);
    assert_eq!(resumed.policy_epoch, revoked.policy_epoch);
    assert_eq!(store.purge_jobs().unwrap().len(), 1);
}

#[test]
fn stale_cas_and_counter_overflow_roll_back_every_write() {
    let (_temp, root, store) = setup();
    let other = SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
    let first = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let before = store.status().unwrap();
    assert!(matches!(
        other.revoke_selection(zero(), &first.value.id, None, 20),
        Err(PortError::GenerationMismatch(_))
    ));
    assert!(matches!(
        other.add_selection(zero(), request(SearchProvider::Codex, "R", RootKind::Root)),
        Err(PortError::GenerationMismatch(_))
    ));
    assert_eq!(store.status().unwrap(), before);
    assert!(store.purge_jobs().unwrap().is_empty());
    let conn = raw(&root);
    conn.execute("UPDATE control_meta SET control_seq=?1", [i64::MAX])
        .unwrap();
    let before = store.status().unwrap();
    assert!(
        store
            .revoke_selection(
                ControlSeq::new(i64::MAX).unwrap(),
                &first.value.id,
                None,
                20
            )
            .is_err()
    );
    assert_eq!(store.status().unwrap(), before);
    assert!(store.purge_jobs().unwrap().is_empty());
    conn.execute("UPDATE control_meta SET policy_epoch=?1", [i64::MAX])
        .unwrap();
    let before = store.status().unwrap();
    assert!(
        store
            .add_selection(
                ControlSeq::new(i64::MAX).unwrap(),
                request(SearchProvider::Codex, "R", RootKind::Root)
            )
            .is_err()
    );
    assert_eq!(store.status().unwrap(), before);
}

#[test]
fn explicit_restart_sequence_and_autostart_mirror_preserve_pause_and_permission() {
    let (_temp, _root, store) = setup();
    let paused = store
        .set_desired_updates(zero(), DesiredUpdates::Paused)
        .unwrap();
    let before = store.status().unwrap();
    let first = store.request_background_start(paused.control_seq).unwrap();
    let second = store.request_background_start(first.control_seq).unwrap();
    assert_eq!(second.value.get(), first.value.get() + 1);
    assert_eq!(
        store.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert_eq!(
        store.status().unwrap().policy.policy_epoch,
        before.policy.policy_epoch
    );
    assert!(matches!(
        store.request_background_start(first.control_seq),
        Err(PortError::GenerationMismatch(_))
    ));
    let enabled = store
        .set_autostart_enabled(second.control_seq, true)
        .unwrap();
    let after = store.status().unwrap();
    assert!(after.autostart_enabled);
    assert_eq!(after.restart_request_seq, second.value);
    assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    assert_eq!(after.policy.policy_epoch, before.policy.policy_epoch);
    assert!(
        !store
            .set_autostart_enabled(enabled.control_seq, true)
            .unwrap()
            .changed
    );
    store
        .set_autostart_enabled(enabled.control_seq, false)
        .unwrap();
    assert!(!store.status().unwrap().autostart_enabled);
}

#[test]
fn supervisor_failure_requires_its_actual_root_lock_and_preserves_worker_authority() {
    let (_temp, root, store) = setup();
    let (_other_temp, other_root, _other) = setup();
    let before = store.status().unwrap();
    let worker_before = store.background_status().unwrap();
    let wrong = exclusive_guard(&other_root, LockKind::Supervisor);
    assert!(
        store
            .report_supervisor_failure(before.policy.control_seq, &wrong, true)
            .is_err()
    );
    let background = exclusive_guard(&root, LockKind::Background);
    assert!(
        store
            .report_supervisor_failure(before.policy.control_seq, &background, true)
            .is_err()
    );
    let supervisor = exclusive_guard(&root, LockKind::Supervisor);
    let failed = store
        .report_supervisor_failure(before.policy.control_seq, &supervisor, true)
        .unwrap();
    assert!(store.status().unwrap().supervisor_failed);
    assert_eq!(
        store.background_status().unwrap().worker,
        worker_before.worker
    );
    assert_eq!(
        store.status().unwrap().policy.policy_epoch,
        before.policy.policy_epoch
    );
    assert!(
        !store
            .report_supervisor_failure(failed.control_seq, &supervisor, true)
            .unwrap()
            .changed
    );
    store
        .report_supervisor_failure(failed.control_seq, &supervisor, false)
        .unwrap();
    assert!(!store.status().unwrap().supervisor_failed);
}

#[test]
fn corrupt_enums_ranges_schema_and_unknown_future_rows_fail_closed() {
    for sql in [
        "PRAGMA ignore_check_constraints=ON; UPDATE control_meta SET desired_updates='private-secret'",
        "UPDATE worker_state SET effective_state='unexpected'",
        "UPDATE control_meta SET control_seq=-1",
        "UPDATE control_meta SET next_cycle_seq=-1",
        "UPDATE control_meta SET restart_request_seq=-1",
        "UPDATE control_meta SET maintenance_phase='unknown'",
        "UPDATE control_meta SET schema_version=3",
        "UPDATE control_meta SET installation_id='invalid identity'",
        "PRAGMA user_version=3",
        "PRAGMA application_id=0",
        "DELETE FROM control_meta",
        "DROP TABLE exclusions",
        "INSERT INTO source_updates(source_id,provider_id,coverage,update_state,backfill_state) VALUES('source','codex','unknown','idle','pending')",
    ] {
        let (_temp, root, store) = setup();
        raw(&root).execute_batch(sql).unwrap();
        let error = store.status().unwrap_err();
        assert!(matches!(error, PortError::SchemaIncompatible(_)), "{sql}");
        assert!(!format!("{error:?}").contains("private-secret"));
        assert!(SqliteControlStore::open_existing_writable(&root, &id("installation")).is_err());
        assert!(SqliteControlStore::open_read_only(&root, &id("installation")).is_err());
        assert!(SqliteControlStore::open_current_read_only(&root).is_err());
        assert!(SqliteControlStore::open_current_writable(&root).is_err());
    }
}

#[test]
fn persisted_selection_exclusion_intent_and_purge_decoders_validate_all_fields() {
    for sql in [
        "UPDATE selections SET provider_id='unknown'",
        "UPDATE selections SET canonical_locator='relative'",
        "UPDATE selections SET revision=-1",
        "UPDATE selections SET created_at_ms=-1",
        "UPDATE exclusions SET source_id='unexpected' WHERE region_kind='exact'",
        "UPDATE exclusions SET created_policy_epoch=-1",
        "PRAGMA ignore_check_constraints=ON; UPDATE revocation_intents SET state='unknown'",
        "UPDATE revocation_intents SET settled_at_ms=1",
        "UPDATE purge_jobs SET attempts=-1",
        "PRAGMA ignore_check_constraints=ON; UPDATE purge_jobs SET state='unknown'",
        "UPDATE purge_jobs SET selection_revision=-1",
    ] {
        let (_temp, root, store) = setup();
        let s = store
            .add_selection(
                zero(),
                request(SearchProvider::Claude, "R/F", RootKind::Exact),
            )
            .unwrap();
        retry_expected_success(|| store.revoke_selection(s.control_seq, &s.value.id, None, 20))
            .unwrap();
        raw(&root).execute_batch(sql).unwrap();
        assert!(
            matches!(store.status(), Err(PortError::SchemaIncompatible(_))),
            "{sql}"
        );
    }
}

#[test]
fn lifecycle_status_rejects_schema_and_core_policy_corruption_without_mutation() {
    for sql in [
        "PRAGMA user_version=3",
        "PRAGMA application_id=0",
        "UPDATE control_meta SET schema_version=3",
        "DROP INDEX cycles_runtime_state",
        "PRAGMA ignore_check_constraints=ON; UPDATE control_meta SET desired_updates='private-secret'",
        "UPDATE control_meta SET policy_epoch=control_seq+1",
        "UPDATE control_meta SET maintenance_phase='unknown'",
        "UPDATE selections SET canonical_locator='relative'",
        "UPDATE selections SET revision=999999",
        "UPDATE exclusions SET source_id='unexpected' WHERE region_kind='exact'",
        "DELETE FROM purge_jobs",
        "PRAGMA ignore_check_constraints=ON; UPDATE purge_jobs SET state='unknown'",
        "UPDATE revocation_intents SET settled_at_ms=1",
        "INSERT INTO private_artifacts VALUES('corrupt-artifact','unknown','backups/corrupt-artifact/catalog.db',0,NULL,'unknown',NULL)",
        "INSERT INTO backup_manifests VALUES('corrupt-backup','unknown','backups/corrupt-backup/catalog.db','catalog_a',0,22,'',0,'unknown',10)",
    ] {
        let (_temp, root, store) = setup();
        let selected = retry_expected_success(|| {
            store.add_selection(
                zero(),
                request(SearchProvider::Claude, "R/F", RootKind::Exact),
            )
        })
        .unwrap();
        retry_expected_success(|| {
            store.revoke_selection(selected.control_seq, &selected.value.id, None, 20)
        })
        .unwrap();
        raw(&root).execute_batch(sql).unwrap();
        let before = control_rows(&root);
        let end = std::time::Instant::now() + std::time::Duration::from_secs(8);
        let error = store
            .with_runtime_deadline(end, || store.lifecycle_status())
            .unwrap_err();
        assert!(matches!(error, PortError::SchemaIncompatible(_)), "{sql}");
        assert!(!format!("{error:?}").contains("private-secret"));
        assert!(matches!(
            store.with_runtime_deadline(end, || store.status()),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert!(control_rows(&root) == before, "{sql}");
    }
}

#[test]
fn unsupported_or_empty_existing_database_is_never_initialized_or_reset() {
    let (_temp, root, store) = setup();
    drop(store);
    let conn = raw(&root);
    conn.execute_batch("PRAGMA user_version=77").unwrap();
    drop(conn);
    assert!(SqliteControlStore::open_existing_writable(&root, &id("installation")).is_err());
    assert_eq!(
        raw(&root)
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        77
    );
    let empty_root = root.join("empty");
    // A failed/incomplete authorized create is retained, never silently reset.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&empty_root)
            .unwrap();
    }
    #[cfg(windows)]
    std::fs::create_dir(&empty_root).unwrap();
    let path = SqliteControlStore::path(&empty_root);
    std::fs::write(&path, []).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(
        SqliteControlStore::create(&empty_root, &id("installation"), DesiredUpdates::Running)
            .is_err()
    );
    assert!(SqliteControlStore::open_read_only(&empty_root, &id("installation")).is_err());
    assert!(SqliteControlStore::open_current_read_only(&empty_root).is_err());
    assert!(SqliteControlStore::open_current_writable(&empty_root).is_err());
    assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
}

#[test]
fn invalid_values_and_debug_are_bounded_and_private() {
    for value in ["", "../private", "source:private", "line\nfeed"] {
        assert!(ControlId::parse(value).is_err());
    }
    for value in ["relative", "../R", "C:relative", "", "\0"] {
        assert!(CanonicalLocator::parse(value).is_err());
    }
    assert!(ControlSeq::new(-1).is_err());
    assert!(PolicyEpoch::new(-1).is_err());
    let (_temp, _root, store) = setup();
    let mut r = request(SearchProvider::Claude, "Secret/F", RootKind::Exact);
    r.now_ms = -1;
    assert!(store.add_selection(zero(), r).is_err());
    let r = store
        .add_selection(
            zero(),
            request(SearchProvider::Claude, "Secret/F", RootKind::Exact),
        )
        .unwrap();
    assert!(!format!("{r:?}").contains("Secret"));
    assert!(!format!("{:?}", id("private_identity_value")).contains("private_identity_value"));
    assert!(
        MaintenanceFence {
            state: MaintenanceState::Idle,
            owner: Some(id("owner")),
            phase: None
        }
        .validate()
        .is_err()
    );
}

#[cfg(windows)]
#[test]
fn windows_case_variants_and_verbatim_paths_cannot_bypass_denial() {
    let (_temp, _root, store) = setup();
    let parent = retry_expected_success(|| {
        store.add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
    })
    .unwrap();
    let f = retry_expected_success(|| {
        store.add_selection(
            parent.control_seq,
            request(SearchProvider::Claude, "R/F", RootKind::Exact),
        )
    })
    .unwrap();
    let revoked =
        retry_expected_success(|| store.revoke_selection(f.control_seq, &f.value.id, None, 20))
            .unwrap();
    // A second explicitly added differently-cased root still cannot regrant F.
    retry_expected_success(|| {
        store.add_selection(
            revoked.control_seq,
            request(SearchProvider::Claude, "r", RootKind::Root),
        )
    })
    .unwrap();
    let policy = store.status().unwrap().policy;
    assert!(!allowed(&policy, SearchProvider::Claude, "r/f"));
    assert!(!allowed(&policy, SearchProvider::Claude, "R/f"));
    assert!(allowed(&policy, SearchProvider::Claude, "r/other"));
    assert_eq!(
        CanonicalLocator::from_path(Path::new(r"\\?\C:\synthetic\R\F")).unwrap(),
        locator("R/F")
    );
    assert_eq!(
        CanonicalLocator::from_path(Path::new(r"\\?\UNC\server\share\R")).unwrap(),
        CanonicalLocator::parse(r"\\server\share\R").unwrap()
    );
    for value in [
        r"\\.\C:\synthetic",
        r"C:\synthetic\R\..\F",
        r"C:\synthetic\R\.\F",
        r"C:\synthetic\R\F ",
        r"C:\synthetic\R\F:stream",
        r"C:\synthetic\\R",
    ] {
        assert!(CanonicalLocator::parse(value).is_err(), "{value}");
    }
}

#[test]
fn concurrent_pause_and_revoke_cas_has_one_winner_and_retry_preserves_both() {
    use std::sync::{Arc, Barrier};
    let (_temp, root, store) = setup();
    let selected = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let path = root.clone();
    let sync = barrier.clone();
    let expected = selected.control_seq;
    let first = std::thread::spawn(move || {
        let store = SqliteControlStore::open_existing_writable(&path, &id("installation")).unwrap();
        sync.wait();
        store
            .set_desired_updates(expected, DesiredUpdates::Paused)
            .map(|_| ())
    });
    let path = root.clone();
    let selection = selected.value.id.clone();
    let second = std::thread::spawn(move || {
        let store = SqliteControlStore::open_existing_writable(&path, &id("installation")).unwrap();
        barrier.wait();
        store
            .revoke_selection(expected, &selection, None, 50)
            .map(|_| ())
    });
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Err(PortError::GenerationMismatch(_))))
            .count(),
        1
    );
    let current = store.status().unwrap();
    let paused = store
        .set_desired_updates(current.policy.control_seq, DesiredUpdates::Paused)
        .unwrap();
    store
        .revoke_selection(paused.control_seq, &selected.value.id, None, 51)
        .unwrap();
    let final_state = store.status().unwrap();
    assert_eq!(final_state.desired_updates, DesiredUpdates::Paused);
    assert!(!allowed(&final_state.policy, SearchProvider::Claude, "R/F"));
    assert_eq!(store.purge_jobs().unwrap().len(), 1);
}

#[test]
fn sqlite_writer_contention_is_bounded_and_never_partially_changes_policy() {
    let (_temp, root, store) = setup();
    let conn = raw(&root);
    let before = store.status().unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = store
        .set_desired_updates(zero(), DesiredUpdates::Paused)
        .unwrap_err();
    assert!(matches!(error, PortError::WriterBusy(_)));
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(store.status().unwrap(), before);
}

#[test]
fn repeated_revive_revoke_uses_latest_epoch_not_random_job_order() {
    let (_temp, root, store) = setup();
    let s = store
        .add_selection(
            zero(),
            request(SearchProvider::Claude, "R/F", RootKind::Exact),
        )
        .unwrap();
    let first = store
        .revoke_selection(s.control_seq, &s.value.id, None, 20)
        .unwrap();
    let revived = store
        .add_selection(
            first.control_seq,
            request(SearchProvider::Claude, "R/F", RootKind::Exact),
        )
        .unwrap();
    let second = store
        .revoke_selection(revived.control_seq, &s.value.id, None, 30)
        .unwrap();
    assert!(second.policy_epoch > first.policy_epoch);
    let conn = raw(&root);
    conn.execute(
        "UPDATE purge_jobs SET job_id='zzz_older' WHERE policy_epoch=?1",
        [first.policy_epoch.get()],
    )
    .unwrap();
    conn.execute(
        "UPDATE purge_jobs SET job_id='aaa_newer' WHERE policy_epoch=?1",
        [second.policy_epoch.get()],
    )
    .unwrap();
    let again = store
        .revoke_selection(second.control_seq, &s.value.id, None, 40)
        .unwrap();
    assert!(!again.changed);
    assert_eq!(again.value.intent, second.value.intent);
    assert_eq!(again.value.purge_job.id, id("aaa_newer"));
    assert_eq!(again.value.purge_job.policy_epoch, second.policy_epoch);
    assert_eq!(store.purge_jobs().unwrap().len(), 2);
    assert_eq!(store.status().unwrap().policy.exclusions.len(), 1);
}

// Tests hold a real OS exclusive lifecycle lock. Production composition must
// bind its corresponding guard to the actual installation, not a heartbeat.
struct TestWorker {
    installation: ControlId,
    boot: ControlId,
    root: RootIdentity,
    lock: ExclusiveGuard,
}
impl TestWorker {
    fn acquire(root: &Path, boot: &str) -> Self {
        let identity = RootIdentity::read(root).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let lock = loop {
            match ExclusiveGuard::try_acquire(root, LockKind::Background) {
                Ok(lock) => break lock,
                Err(PortError::WriterBusy(_)) if std::time::Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("worker lock acquisition failed: {error:?}"),
            }
        };
        Self {
            installation: id("installation"),
            boot: id(boot),
            root: identity,
            lock,
        }
    }
}
impl WorkerAuthority for TestWorker {
    fn installation_id(&self) -> &ControlId {
        &self.installation
    }
    fn boot_id(&self) -> &ControlId {
        &self.boot
    }
    fn root_binding(&self) -> PhysicalRootBinding {
        self.lock.root_identity().binding()
    }
    fn validate(&self) -> agent_session_grep_ports::PortResult<()> {
        if self.lock.kind() != &LockKind::Background || self.lock.root_identity() != self.root {
            return Err(PortError::InvalidRequest(
                "test worker binding changed".into(),
            ));
        }
        Ok(())
    }
}
fn revision(selection: &Selection) -> SelectionRevision {
    SelectionRevision {
        selection_id: selection.id.clone(),
        revision: selection.revision,
        root_identity: selection.root_identity.clone().unwrap(),
    }
}
fn current(store: &SqliteControlStore) -> ControlSeq {
    retry_expected_success(|| store.status())
        .unwrap()
        .policy
        .control_seq
}
fn latest(store: &SqliteControlStore, selected: &SelectionRevision, now_ms: i64) -> LatestBarrier {
    match retry_expected_success(|| {
        store.admit_latest(
            current(store),
            LatestRequest {
                selections: vec![selected.clone()],
                max_wait_ms: 1000,
                now_ms,
            },
        )
    })
    .unwrap()
    .value
    {
        LatestAdmission::Queued(b) => b,
        blocked => panic!("{blocked:?}"),
    }
}
fn worker_setup() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    SqliteControlStore,
    TestWorker,
    SelectionRevision,
) {
    let (temp, root, store) = setup();
    let selected = retry_expected_success(|| {
        store.add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
    })
    .unwrap();
    let worker = TestWorker::acquire(&root, "boot_a");
    retry_expected_success(|| store.register_worker(selected.control_seq, &worker, 10, 100))
        .unwrap();
    (temp, root, store, worker, revision(&selected.value))
}
fn set_catalog(store: &SqliteControlStore, worker: &TestWorker, incarnation: &str) {
    let owner = id("recovery_owner");
    retry_expected_success(|| {
        store.set_maintenance(
            current(store),
            &owner,
            MaintenanceFence {
                state: MaintenanceState::Recovering,
                owner: Some(owner.clone()),
                phase: Some(MaintenancePhase::Reconciling),
            },
        )
    })
    .unwrap();
    retry_expected_success(|| store.reset_progress(current(store), worker, &id(incarnation), 101))
        .unwrap();
    retry_expected_success(|| {
        store.set_maintenance(current(store), &owner, MaintenanceFence::idle())
    })
    .unwrap();
}
fn source_ack(c: &ObservationCycle, s: &SelectionRevision, receipt: bool) -> SourceAcknowledgement {
    SourceAcknowledgement {
        source_id: id("source_f"),
        provider: SearchProvider::Claude,
        token: c.token.clone(),
        selection: s.clone(),
        attempted_at_ms: 200,
        coverage: if receipt {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        update_state: UpdateState::Idle,
        backfill_state: BackfillState::Complete,
        error: None,
        receipt: receipt.then(|| SourceReceiptSummary {
            token: c.token.clone(),
            revision: id("revision_digest"),
            catalog_incarnation: id("catalog_a"),
            catalog_generation: ControlSeq::new(7).unwrap(),
        }),
        confirmation: None,
    }
}

#[test]
fn queued_barriers_coalesce_and_started_cycle_never_accepts_new_admission() {
    let (_temp, root, store, worker, s) = worker_setup();
    let a = latest(&store, &s, 500);
    let b = latest(&store, &s, 1); // Clock moves backwards; control sequence is authority.
    assert_eq!(a.required_cycle_seq, b.required_cycle_seq);
    assert!(b.admission_control_seq > a.admission_control_seq);
    let c = store
        .start_cycle(current(&store), &worker, a.required_cycle_seq, 0)
        .unwrap()
        .value;
    assert!(c.started_control_seq.unwrap() > b.admission_control_seq);
    let later = latest(&store, &s, 2);
    assert!(later.required_cycle_seq > c.token.cycle_seq);
    assert!(
        store
            .start_cycle(current(&store), &worker, later.required_cycle_seq, 3)
            .is_err()
    );
    retry_expected_success(|| {
        store.acknowledge_discovery(
            current(&store),
            &worker,
            DiscoveryAcknowledgement {
                token: c.token.clone(),
                selection: s.clone(),
                complete: true,
                discovered_count: 0,
                observed_count: 0,
                committed_count: 0,
                error: None,
            },
        )
    })
    .unwrap();
    retry_expected_success(|| {
        store.finish_cycle(
            current(&store),
            &worker,
            c.token.cycle_seq,
            CycleFinish::Committed,
            3,
        )
    })
    .unwrap();
    assert_eq!(
        store.barrier(&a.id).unwrap().state,
        BarrierState::AwaitingCatalog
    );
    assert_eq!(
        store.barrier(&b.id).unwrap().completed_cycle_seq,
        Some(c.token.cycle_seq)
    );
    assert_eq!(
        store.barrier(&later.id).unwrap().state,
        BarrierState::Pending
    );
    let reopened = SqliteControlStore::open_read_only(&root, &id("installation")).unwrap();
    assert_eq!(
        reopened.cycle(c.token.cycle_seq).unwrap(),
        store.cycle(c.token.cycle_seq).unwrap()
    );
}

#[test]
fn concurrent_latest_admission_and_cycle_start_serialize_without_old_observations() {
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    let (_temp, root, store, worker, s) = worker_setup();
    let end = Instant::now() + Duration::from_secs(8);
    let (first, before, before_runtime, queued, before_rows) = store
        .with_runtime_deadline(end, || {
            let first = latest(&store, &s, 100);
            Ok((
                first.clone(),
                store.status()?,
                store.background_status()?,
                store.cycle(first.required_cycle_seq)?,
                control_rows(&root),
            ))
        })
        .unwrap();
    let expected = before.policy.control_seq;
    let sync = Arc::new(Barrier::new(2));
    // Race one call per side at the same sequence; neither mutation is retried.
    let (start, admission) = std::thread::scope(|scope| {
        let sync1 = sync.clone();
        let path = root.clone();
        let worker_ref = &worker;
        let t1 = scope.spawn(move || {
            let store = SqliteControlStore::open_existing_writable_with_deadline(
                &path,
                &id("installation"),
                end,
            )
            .unwrap();
            store.with_runtime_deadline(end, || {
                sync1.wait();
                store.start_cycle(expected, worker_ref, first.required_cycle_seq, 101)
            })
        });
        let path = root.clone();
        let selected = s.clone();
        let t2 = scope.spawn(move || {
            let store = SqliteControlStore::open_existing_writable_with_deadline(
                &path,
                &id("installation"),
                end,
            )
            .unwrap();
            store.with_runtime_deadline(end, || {
                sync.wait();
                store.admit_latest(
                    expected,
                    LatestRequest {
                        selections: vec![selected],
                        max_wait_ms: 1000,
                        now_ms: 102,
                    },
                )
            })
        });
        (t1.join().unwrap(), t2.join().unwrap())
    });
    assert_eq!(
        usize::from(start.is_ok()) + usize::from(admission.is_ok()),
        1
    );
    store
        .with_runtime_deadline(end, || {
            let committed_seq = ControlSeq::new(expected.get() + 1).unwrap();
            let barrier_count = |rows: &[(String, Vec<String>)]| {
                rows.iter()
                    .find(|(name, _)| name == "barriers")
                    .unwrap()
                    .1
                    .len()
            };
            let after_rows = control_rows(&root);
            match (start, admission) {
                (Ok(c), Err(PortError::GenerationMismatch(_) | PortError::WriterBusy(_))) => {
                    assert!(c.changed);
                    assert_eq!(c.control_seq, committed_seq);
                    assert_eq!(c.value.state, CycleState::Observing);
                    assert_eq!(c.value.started_control_seq, Some(committed_seq));
                    assert!(committed_seq > first.admission_control_seq);
                    assert_eq!(store.cycle(first.required_cycle_seq)?, c.value);
                    assert_eq!(barrier_count(&after_rows), barrier_count(&before_rows));
                }
                (Err(PortError::GenerationMismatch(_) | PortError::WriterBusy(_)), Ok(b)) => {
                    assert!(b.changed);
                    assert_eq!(b.control_seq, committed_seq);
                    let LatestAdmission::Queued(b) = b.value else {
                        panic!("unexpected block")
                    };
                    assert_eq!(b.required_cycle_seq, first.required_cycle_seq);
                    assert_eq!(b.admission_control_seq, committed_seq);
                    assert!(b.admission_control_seq > first.admission_control_seq);
                    assert_eq!(store.barrier(&b.id)?, b);
                    assert_eq!(store.cycle(first.required_cycle_seq)?, queued);
                    assert_eq!(barrier_count(&after_rows), barrier_count(&before_rows) + 1);
                }
                other => panic!("unexpected race: {other:?}"),
            }
            assert_eq!(store.barrier(&first.id)?, first);
            let after_runtime = store.background_status()?;
            assert_eq!(after_runtime.control_seq, committed_seq);
            assert_eq!(after_runtime.next_cycle_seq, before_runtime.next_cycle_seq);
            assert_eq!(after_runtime.worker, before_runtime.worker);
            let mut expected_status = before;
            expected_status.policy.control_seq = committed_seq;
            assert_eq!(store.status()?, expected_status);
            Ok(())
        })
        .unwrap();
}

#[test]
fn pause_abort_and_resume_never_relabels_previous_observation() {
    let (_temp, _root, store, worker, s) = worker_setup();
    let b = latest(&store, &s, 110);
    let c = store
        .start_cycle(current(&store), &worker, b.required_cycle_seq, 111)
        .unwrap()
        .value;
    store
        .set_desired_updates(current(&store), DesiredUpdates::Paused)
        .unwrap();
    assert_eq!(
        store.cycle(c.token.cycle_seq).unwrap().state,
        CycleState::Aborted
    );
    let attempt = store
        .admit_latest(
            current(&store),
            LatestRequest {
                selections: vec![s.clone()],
                max_wait_ms: 1000,
                now_ms: 112,
            },
        )
        .unwrap();
    assert_eq!(
        attempt.value,
        LatestAdmission::Blocked(BackgroundFailure::Paused)
    );
    assert!(!attempt.changed);
    assert_eq!(
        store.barrier(&b.id).unwrap().error,
        Some(BackgroundFailure::Paused)
    );
    assert!(
        store
            .heartbeat_worker(current(&store), &worker, UpdateState::Running, None, 113)
            .is_err()
    );
    store
        .heartbeat_worker(current(&store), &worker, UpdateState::Paused, None, 1)
        .unwrap();
    assert!(
        store
            .acknowledge_source(current(&store), &worker, source_ack(&c, &s, false))
            .is_err()
    );
    store
        .set_desired_updates(current(&store), DesiredUpdates::Running)
        .unwrap();
    store
        .heartbeat_worker(current(&store), &worker, UpdateState::Idle, None, 114)
        .unwrap();
    assert!(latest(&store, &s, 114).required_cycle_seq > c.token.cycle_seq);
    assert_eq!(
        store.cycle(c.token.cycle_seq).unwrap().started_control_seq,
        c.started_control_seq
    );
}

#[test]
fn restart_retains_committed_receipt_tokens_clears_candidates_and_resets_progress_forward() {
    let (_temp, root, store, worker, s) = worker_setup();
    set_catalog(&store, &worker, "catalog_a");
    let b = latest(&store, &s, 120);
    let c = store
        .start_cycle(current(&store), &worker, b.required_cycle_seq, 121)
        .unwrap()
        .value;
    let acknowledged = store
        .acknowledge_source(current(&store), &worker, source_ack(&c, &s, true))
        .unwrap();
    assert_eq!(acknowledged.value.coverage, Coverage::Complete);
    assert_eq!(store.barrier(&b.id).unwrap().state, BarrierState::Pending);
    let mut held = source_ack(&c, &s, false);
    held.update_state = UpdateState::Deferred;
    held.error = Some(BackgroundFailure::RewritePending);
    held.confirmation = Some(PendingConfirmation {
        kind: ConfirmationKind::Rewrite {
            candidate_digest: id("candidate_digest"),
        },
        first_cycle: c.token.cycle_seq,
        confirm_cycle: None,
        worker_boot_id: c.token.worker_boot_id.clone(),
        root_identity: s.root_identity.clone(),
        policy_epoch: c.policy_epoch,
        first_monotonic_ms: ControlSeq::new(55).unwrap(),
    });
    store
        .acknowledge_source(current(&store), &worker, held)
        .unwrap();
    assert!(
        store
            .source_progress(&id("source_f"))
            .unwrap()
            .unwrap()
            .confirmation
            .is_some()
    );
    drop(worker);
    let reboot = TestWorker::acquire(&root, "boot_b");
    store
        .register_worker(current(&store), &reboot, 10, 0)
        .unwrap();
    let retained = store.source_progress(&id("source_f")).unwrap().unwrap();
    assert_eq!(retained.coverage, Coverage::Partial);
    assert_eq!(retained.error, Some(BackgroundFailure::WorkerRestarted));
    assert!(retained.confirmation.is_none());
    assert_eq!(retained.receipt, acknowledged.value.receipt);
    let old = store.cycle(c.token.cycle_seq).unwrap();
    assert_eq!(old.state, CycleState::Aborted);
    assert_eq!(old.token, c.token);
    assert_eq!(old.started_control_seq, c.started_control_seq);
    assert!(latest(&store, &s, 122).required_cycle_seq > old.token.cycle_seq);
    store
        .set_desired_updates(current(&store), DesiredUpdates::Paused)
        .unwrap();
    set_catalog(&store, &reboot, "catalog_b");
    let reset = store.source_progress(&id("source_f")).unwrap().unwrap();
    assert_eq!(reset.coverage, Coverage::Empty);
    assert!(reset.receipt.is_none());
    assert!(reset.last_observation.is_none());
    assert_eq!(
        store.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert_eq!(
        store.status().unwrap().catalog_incarnation,
        Some(id("catalog_b"))
    );
    assert_eq!(store.barrier(&b.id).unwrap().state, BarrierState::Blocked);
}

#[test]
fn worker_ownership_rejects_old_boot_and_new_boot_never_resumes_pause() {
    let (_temp, root, store, worker, s) = worker_setup();
    let b = latest(&store, &s, 130);
    store
        .start_cycle(current(&store), &worker, b.required_cycle_seq, 131)
        .unwrap();
    store.stop_worker(current(&store), &worker, 132).unwrap();
    assert_eq!(
        store.cycle(b.required_cycle_seq).unwrap().state,
        CycleState::Aborted
    );
    store
        .set_desired_updates(current(&store), DesiredUpdates::Paused)
        .unwrap();
    drop(worker);
    let reboot = TestWorker::acquire(&root, "boot_b");
    store
        .register_worker(current(&store), &reboot, 12, 2)
        .unwrap();
    assert_eq!(
        store.background_status().unwrap().worker.state,
        UpdateState::Paused
    );
    assert_eq!(
        store.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    let stale = store.bind_worker(&reboot.lock, id("boot_a")).unwrap();
    assert!(matches!(
        store.heartbeat_worker(current(&store), &stale, UpdateState::Paused, None, 3),
        Err(PortError::GenerationMismatch(_))
    ));
    assert!(matches!(
        store.register_worker(current(&store), &stale, 12, 4),
        Err(PortError::GenerationMismatch(_))
    ));
}

#[test]
fn background_corrupt_rows_fail_closed_without_defaulting_to_current() {
    for sql in [
        "UPDATE worker_state SET last_error='private-error-secret'",
        "UPDATE worker_state SET pid_hint=-1",
        "PRAGMA ignore_check_constraints=ON; UPDATE cycles SET state='unknown'",
        "UPDATE cycles SET started_control_seq=admitted_control_seq",
        "UPDATE cycle_selections SET discovery_complete=2",
        "UPDATE cycle_selections SET committed_count=-1",
        "UPDATE cycle_selections SET root_identity=NULL",
        "UPDATE barriers SET state='satisfied'",
        "UPDATE barriers SET requested_wait_ms=-1",
        "UPDATE barriers SET admission_control_seq=999999",
        "UPDATE barrier_selections SET selection_revision=99",
        "UPDATE source_updates SET coverage='current'",
        "UPDATE source_updates SET update_state='unknown'",
        "UPDATE source_updates SET backfill_state='unknown'",
        "UPDATE source_updates SET receipt_cycle=9999",
        "UPDATE source_updates SET catalog_generation=-1",
        "UPDATE source_updates SET confirmation_boot_id='orphan'",
    ] {
        let (_temp, root, store, worker, s) = worker_setup();
        set_catalog(&store, &worker, "catalog_a");
        let b = latest(&store, &s, 140);
        let c = store
            .start_cycle(current(&store), &worker, b.required_cycle_seq, 141)
            .unwrap()
            .value;
        store
            .acknowledge_source(current(&store), &worker, source_ack(&c, &s, true))
            .unwrap();
        raw(&root).execute_batch(sql).unwrap();
        let error = store.background_status().unwrap_err();
        assert!(matches!(error, PortError::SchemaIncompatible(_)), "{sql}");
        assert!(!format!("{error:?}").contains("private-error-secret"));
        assert!(
            SqliteControlStore::open_read_only(&root, &id("installation")).is_err(),
            "{sql}"
        );
    }
}

#[test]
fn lifecycle_status_does_not_validate_runtime_proof_or_enable_mutations() {
    for sql in [
        "UPDATE worker_state SET effective_state='unknown'",
        "UPDATE cycles SET started_control_seq=admitted_control_seq",
        "UPDATE cycle_selections SET discovery_complete=2",
        "UPDATE barriers SET state='satisfied'",
        "UPDATE barrier_selections SET selection_revision=99",
        "UPDATE source_updates SET coverage='current'",
        "UPDATE source_updates SET receipt_cycle=9999",
    ] {
        let (_temp, root, store, worker, selection) = worker_setup();
        set_catalog(&store, &worker, "catalog_a");
        let barrier = latest(&store, &selection, 140);
        let cycle = retry_expected_success(|| {
            store.start_cycle(current(&store), &worker, barrier.required_cycle_seq, 141)
        })
        .unwrap()
        .value;
        retry_expected_success(|| {
            store.acknowledge_source(
                current(&store),
                &worker,
                source_ack(&cycle, &selection, true),
            )
        })
        .unwrap();
        let before_status = retry_expected_success(|| store.status()).unwrap();
        raw(&root).execute_batch(sql).unwrap();
        let before = control_rows(&root);
        store
            .with_runtime_deadline(
                std::time::Instant::now() + std::time::Duration::from_secs(8),
                || {
                    assert_eq!(store.lifecycle_status()?, before_status);
                    assert!(
                        matches!(store.status(), Err(PortError::SchemaIncompatible(_))),
                        "{sql}"
                    );
                    assert!(
                        matches!(
                            store.cycle(cycle.token.cycle_seq),
                            Err(PortError::SchemaIncompatible(_))
                        ),
                        "{sql}"
                    );
                    assert!(
                        matches!(
                            store.barrier(&barrier.id),
                            Err(PortError::SchemaIncompatible(_))
                        ),
                        "{sql}"
                    );
                    assert!(
                        matches!(
                            store.set_desired_updates(
                                before_status.policy.control_seq,
                                DesiredUpdates::Paused
                            ),
                            Err(PortError::SchemaIncompatible(_))
                        ),
                        "{sql}"
                    );
                    Ok(())
                },
            )
            .unwrap();
        assert!(control_rows(&root) == before, "{sql}");
    }
}

#[test]
fn lifecycle_status_keeps_runtime_front_capacity_refusal() {
    use agent_session_grep_adapters_sqlite::control::MAX_RUNTIME_REFERENCES;

    for injection in [
        "INSERT INTO cycles SELECT value+1,NULL,0,'queued',0,NULL,NULL,NULL FROM n",
        "INSERT INTO barriers SELECT 'corrupt-barrier-'||value,0,0,1,'pending',0,0,NULL,NULL,NULL FROM n",
        "INSERT INTO source_updates(source_id,provider_id,coverage,update_state,backfill_state)
         SELECT 'corrupt-source-'||value,'codex','unknown','unknown','unknown' FROM n",
    ] {
        let (_temp, root, store) = setup();
        let conn = raw(&root);
        // An over-bound corrupt inventory must refuse before runtime row decoding.
        let sql = format!(
            "WITH RECURSIVE n(value) AS (
                 SELECT 0 UNION ALL SELECT value+1 FROM n WHERE value<?1
             ) {injection}"
        );
        conn.execute(&sql, [i64::try_from(MAX_RUNTIME_REFERENCES).unwrap()])
            .unwrap();
        let before = control_rows(&root);
        store
            .with_runtime_deadline(
                std::time::Instant::now() + std::time::Duration::from_secs(8),
                || {
                    for result in [store.lifecycle_status(), store.status()] {
                        assert!(matches!(
                            result,
                            Err(PortError::Backend(reason))
                                if reason == "control runtime dependency capacity exceeded"
                        ));
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert!(control_rows(&root) == before);
    }
}

#[test]
fn cycle_allocation_overflow_and_stale_revisions_have_no_partial_rows() {
    let (_temp, root, store, _worker, s) = worker_setup();
    let mut stale = s.clone();
    stale.revision = zero();
    let before = store.background_status().unwrap();
    assert!(store.queue_cycle(current(&store), vec![stale]).is_err());
    assert_eq!(store.background_status().unwrap(), before);
    raw(&root)
        .execute("UPDATE control_meta SET next_cycle_seq=?1", [i64::MAX])
        .unwrap();
    assert!(
        store
            .admit_latest(
                current(&store),
                LatestRequest {
                    selections: vec![s],
                    max_wait_ms: 10,
                    now_ms: 150
                }
            )
            .is_err()
    );
    let conn = raw(&root);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM cycles", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM barriers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        store.background_status().unwrap().control_seq,
        before.control_seq
    );
}

#[test]
fn discovery_completion_can_precede_content_ack_and_failure_retains_old_receipt() {
    let (_temp, _root, store, worker, s) = worker_setup();
    set_catalog(&store, &worker, "catalog_a");
    let b = latest(&store, &s, 160);
    let c = store
        .start_cycle(current(&store), &worker, b.required_cycle_seq, 161)
        .unwrap()
        .value;
    let mut discovery = DiscoveryAcknowledgement {
        token: c.token.clone(),
        selection: s.clone(),
        complete: true,
        discovered_count: 1,
        observed_count: 0,
        committed_count: 0,
        error: None,
    };
    store
        .acknowledge_discovery(current(&store), &worker, discovery.clone())
        .unwrap();
    assert!(
        store
            .finish_cycle(
                current(&store),
                &worker,
                c.token.cycle_seq,
                CycleFinish::Committed,
                162
            )
            .is_err()
    );
    let first = store
        .acknowledge_source(current(&store), &worker, source_ack(&c, &s, true))
        .unwrap();
    discovery.observed_count = 1;
    discovery.committed_count = 1;
    store
        .acknowledge_discovery(current(&store), &worker, discovery.clone())
        .unwrap();
    let repeated = store
        .acknowledge_discovery(current(&store), &worker, discovery)
        .unwrap();
    assert!(!repeated.changed);
    store
        .finish_cycle(
            current(&store),
            &worker,
            c.token.cycle_seq,
            CycleFinish::Committed,
            163,
        )
        .unwrap();
    let later = latest(&store, &s, 164);
    let c2 = store
        .start_cycle(current(&store), &worker, later.required_cycle_seq, 165)
        .unwrap()
        .value;
    let mut failed = source_ack(&c2, &s, false);
    failed.error = Some(BackgroundFailure::SourceChanged);
    failed.update_state = UpdateState::Deferred;
    let after = store
        .acknowledge_source(current(&store), &worker, failed)
        .unwrap()
        .value;
    assert_eq!(after.receipt, first.value.receipt);
    assert_eq!(after.last_observation, Some(c2.token));
    assert_eq!(after.coverage, Coverage::Partial);
    assert_eq!(
        store.barrier(&later.id).unwrap().state,
        BarrierState::Pending
    );
}

#[test]
fn revoke_aborts_old_cycle_without_deleting_post_admission_token_proof() {
    let (_temp, _root, store, worker, s) = worker_setup();
    let b = latest(&store, &s, 170);
    let c = store
        .start_cycle(current(&store), &worker, b.required_cycle_seq, 171)
        .unwrap()
        .value;
    store
        .revoke_selection(current(&store), &s.selection_id, None, 172)
        .unwrap();
    let old = store.cycle(c.token.cycle_seq).unwrap();
    assert_eq!(old.state, CycleState::Aborted);
    assert_eq!(old.started_control_seq, c.started_control_seq);
    assert_eq!(
        store.barrier(&b.id).unwrap().error,
        Some(BackgroundFailure::PolicyChanged)
    );
    assert!(
        store
            .acknowledge_source(current(&store), &worker, source_ack(&c, &s, false))
            .is_err()
    );
    assert!(store.queue_cycle(current(&store), vec![s]).is_err());
}

#[test]
fn settlement_requires_drain_and_preserves_denial_pause_and_purge() {
    let (_temp, root, store) = setup();
    let selected = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    store
        .set_desired_updates(current(&store), DesiredUpdates::Paused)
        .unwrap();
    let owner = exclusive_guard(&root, LockKind::PolicyOwner);
    let emitting = shared_guard(&root, LockKind::PolicyEmission);
    let denied = retry_expected_success(|| {
        store.revoke_selection(current(&store), &selected.value.id, None, 20)
    })
    .unwrap();
    assert!(store.status().unwrap().policy.emission_blocked());
    assert!(matches!(
        ExclusiveGuard::try_acquire(&root, LockKind::PolicyEmission),
        Err(PortError::WriterBusy(_))
    ));
    assert!(!allowed(
        &store.status().unwrap().policy,
        SearchProvider::Claude,
        "R/F"
    ));
    // A blocked frame prevents settlement, even after the deny is durable.
    drop(emitting);
    let drained = exclusive_guard(&root, LockKind::PolicyEmission);
    let jobs = store.purge_jobs().unwrap();
    let settled = store
        .settle_revocation(
            current(&store),
            &owner,
            &drained,
            &denied.value.intent.id,
            1,
        )
        .unwrap(); // Wall-clock rollback does not affect OS drain proof.
    assert_eq!(settled.value.state, RevocationState::Settled);
    assert_eq!(settled.policy_epoch, denied.policy_epoch);
    assert!(!store.status().unwrap().policy.emission_blocked());
    assert!(!allowed(
        &store.status().unwrap().policy,
        SearchProvider::Claude,
        "R/F"
    ));
    assert_eq!(
        store.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert_eq!(store.purge_jobs().unwrap(), jobs);
    assert!(
        !store
            .settle_revocation(
                current(&store),
                &owner,
                &drained,
                &denied.value.intent.id,
                50
            )
            .unwrap()
            .changed
    );
}

#[test]
fn settlement_rejects_other_root_and_wrong_lock_without_mutation() {
    let (_temp, root, store) = setup();
    let (_other_temp, other_root, _other_store) = setup();
    let selected = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let denied = store
        .revoke_selection(current(&store), &selected.value.id, None, 20)
        .unwrap();
    let owner = exclusive_guard(&root, LockKind::PolicyOwner);
    let wrong_root = exclusive_guard(&other_root, LockKind::PolicyEmission);
    let wrong_kind = exclusive_guard(&root, LockKind::Background);
    let before = store.status().unwrap();
    for wrong in [&wrong_root, &wrong_kind] {
        assert!(matches!(
            store.settle_revocation(current(&store), &owner, wrong, &denied.value.intent.id, 30),
            Err(PortError::InvalidRequest(_))
        ));
        assert_eq!(store.status().unwrap(), before);
    }
}

#[test]
fn crashed_revoker_can_settle_after_reopen_with_fresh_os_ownership() {
    let (_temp, root, store) = setup();
    let selected = store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    let denied = store
        .revoke_selection(current(&store), &selected.value.id, None, 20)
        .unwrap();
    drop(store);
    let reopened = SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
    assert!(reopened.status().unwrap().policy.emission_blocked());
    let owner = exclusive_guard(&root, LockKind::PolicyOwner);
    let drained = exclusive_guard(&root, LockKind::PolicyEmission);
    let stale = current(&reopened);
    reopened
        .set_desired_updates(stale, DesiredUpdates::Paused)
        .unwrap();
    assert!(matches!(
        reopened.settle_revocation(stale, &owner, &drained, &denied.value.intent.id, 30),
        Err(PortError::GenerationMismatch(_))
    ));
    assert!(reopened.status().unwrap().policy.emission_blocked());
    reopened
        .settle_revocation(
            current(&reopened),
            &owner,
            &drained,
            &denied.value.intent.id,
            30,
        )
        .unwrap();
    assert!(!allowed(
        &reopened.status().unwrap().policy,
        SearchProvider::Claude,
        "R/F"
    ));
}

#[test]
fn worker_authority_binds_real_lock_to_physical_control_root() {
    let (_temp, root, store) = setup();
    let (_other_temp, other_root, _other_store) = setup();
    let lock = exclusive_guard(&root, LockKind::Background);
    let wrong_root = exclusive_guard(&other_root, LockKind::Background);
    let wrong_kind = exclusive_guard(&root, LockKind::PolicyOwner);
    assert!(store.bind_worker(&wrong_root, id("boot_a")).is_err());
    assert!(store.bind_worker(&wrong_kind, id("boot_a")).is_err());
    let worker = store.bind_worker(&lock, id("boot_a")).unwrap();
    worker.validate().unwrap();
    assert!(matches!(
        ExclusiveGuard::try_acquire(&root, LockKind::Background),
        Err(PortError::WriterBusy(_))
    ));
    store
        .register_worker(current(&store), &worker, 1, 1)
        .unwrap();
    assert_eq!(
        store.background_status().unwrap().worker.boot_id,
        Some(id("boot_a"))
    );
}

// Compare every durable table without printing its contents on failure. This
// catches accidental writes even if a rejected mutation failed to bump the CAS.
fn control_rows(root: &Path) -> Vec<(String, Vec<String>)> {
    let conn = raw(root);
    let names = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut stmt = conn
                .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                .unwrap();
            let columns = stmt.column_count();
            let mut rows = stmt
                .query_map([], |row| {
                    let values = (0..columns)
                        .map(|i| row.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(format!("{values:?}"))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows.sort();
            (name, rows)
        })
        .collect()
}

#[test]
fn every_worker_mutation_rejects_other_live_root_even_with_copied_ids() {
    for same_boot in [true, false] {
        let (_temp, root, store, local, selected) = worker_setup();
        let (_other_temp, other_root, other) = setup();
        let other_lock =
            TestWorker::acquire(&other_root, if same_boot { "boot_a" } else { "boot_b" });
        let foreign = other
            .bind_worker(&other_lock.lock, other_lock.boot.clone())
            .unwrap();
        other
            .register_worker(current(&other), &foreign, 10, 100)
            .unwrap();
        assert_eq!(local.installation_id(), foreign.installation_id());
        assert_ne!(local.root_binding(), foreign.root_binding());
        assert_eq!(
            format!("{:?}", foreign.root_binding()),
            "PhysicalRootBinding([private])"
        );
        foreign.validate().unwrap(); // Valid authority, but for another target.

        let barrier = latest(&store, &selected, 110);
        let before = control_rows(&root);
        macro_rules! denied {
            ($operation:literal, $result:expr, $before:expr) => {{
                assert!(
                    matches!($result, Err(PortError::GenerationMismatch(_))),
                    "cross-root {} accepted (same_boot={same_boot})",
                    $operation
                );
                assert!(
                    control_rows(&root) == $before,
                    "{} changed durable state",
                    $operation
                );
            }};
        }
        // Matching boot+PID must not turn cross-root registration into a no-op;
        // a different boot must not replace the real target's still-live worker.
        denied!(
            "register",
            store.register_worker(current(&store), &foreign, 10, 111),
            before
        );
        denied!(
            "heartbeat",
            store.heartbeat_worker(current(&store), &foreign, UpdateState::Running, None, 111),
            before
        );
        denied!(
            "stop",
            store.stop_worker(current(&store), &foreign, 111),
            before
        );
        denied!(
            "start",
            store.start_cycle(current(&store), &foreign, barrier.required_cycle_seq, 111),
            before
        );

        let cycle = store
            .start_cycle(current(&store), &local, barrier.required_cycle_seq, 111)
            .unwrap()
            .value;
        let before = control_rows(&root);
        let discovery = DiscoveryAcknowledgement {
            token: cycle.token.clone(),
            selection: selected.clone(),
            complete: true,
            discovered_count: 0,
            observed_count: 0,
            committed_count: 0,
            error: None,
        };
        denied!(
            "discovery",
            store.acknowledge_discovery(current(&store), &foreign, discovery.clone()),
            before
        );
        denied!(
            "source",
            store.acknowledge_source(
                current(&store),
                &foreign,
                source_ack(&cycle, &selected, false)
            ),
            before
        );
        denied!(
            "finish",
            store.finish_cycle(
                current(&store),
                &foreign,
                cycle.token.cycle_seq,
                CycleFinish::Partial,
                112
            ),
            before
        );
        // The same inputs work with a live guard on the target physical root.
        store
            .acknowledge_discovery(current(&store), &local, discovery)
            .unwrap();
        store
            .acknowledge_source(
                current(&store),
                &local,
                source_ack(&cycle, &selected, false),
            )
            .unwrap();
        store
            .finish_cycle(
                current(&store),
                &local,
                cycle.token.cycle_seq,
                CycleFinish::Partial,
                113,
            )
            .unwrap();

        let owner = id("recovery_owner");
        store
            .set_maintenance(
                current(&store),
                &owner,
                MaintenanceFence {
                    state: MaintenanceState::Recovering,
                    owner: Some(owner.clone()),
                    phase: Some(MaintenancePhase::Reconciling),
                },
            )
            .unwrap();
        let before = control_rows(&root);
        denied!(
            "reset",
            store.reset_progress(current(&store), &foreign, &id("catalog_next"), 114),
            before
        );
        store
            .reset_progress(current(&store), &local, &id("catalog_next"), 114)
            .unwrap();
        assert!(matches!(
            ExclusiveGuard::try_acquire(&root, LockKind::Background),
            Err(PortError::WriterBusy(_))
        ));
        assert!(matches!(
            ExclusiveGuard::try_acquire(&other_root, LockKind::Background),
            Err(PortError::WriterBusy(_))
        ));
    }
}

#[test]
fn worker_binding_accepts_independent_store_handle_on_the_same_physical_root() {
    let (_temp, root, store, worker, _) = worker_setup();
    let reopened = SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
    let authority = store
        .bind_worker(&worker.lock, worker.boot.clone())
        .unwrap();
    assert_eq!(
        authority.root_binding(),
        RootIdentity::read(&root).unwrap().binding()
    );
    reopened
        .heartbeat_worker(
            current(&reopened),
            &authority,
            UpdateState::Running,
            None,
            101,
        )
        .unwrap();
    reopened
        .stop_worker(current(&reopened), &authority, 102)
        .unwrap();
    assert_eq!(
        store.background_status().unwrap().worker.state,
        UpdateState::Offline
    );
}

#[cfg(unix)]
#[test]
fn unix_private_modes_and_symlink_rejection() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (temp, root, store) = setup();
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(SqliteControlStore::path(&root))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let link = temp.path().join("link");
    symlink(&root, &link).unwrap();
    assert!(SqliteControlStore::open_read_only(&link, &id("installation")).is_err());
    assert!(SqliteControlStore::open_current_read_only(&link).is_err());
    assert!(SqliteControlStore::open_current_writable(&link).is_err());
    drop(store);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(SqliteControlStore::open_read_only(&root, &id("installation")).is_err());
    assert!(SqliteControlStore::open_current_read_only(&root).is_err());
    assert!(SqliteControlStore::open_current_writable(&root).is_err());
    assert_eq!(
        std::fs::metadata(root).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn subprocess_revocation_owner() {
    use std::io::{BufRead, Write};
    let Some(root) = std::env::var_os("ASG_TEST_REVOCATION_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let store = SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
    let _owner = exclusive_guard(&root, LockKind::PolicyOwner);
    let selected = store.status().unwrap().policy.selections[0].id.clone();
    store
        .revoke_selection(current(&store), &selected, None, 20)
        .unwrap();
    let _drain = exclusive_guard(&root, LockKind::PolicyEmission);
    println!("revocation-durable");
    std::io::stdout().flush().unwrap();
    let mut command = String::new();
    std::io::stdin().lock().read_line(&mut command).unwrap();
    assert_eq!(command.trim(), "crash");
    // Intentionally bypass Drop: only the OS, not RAII cleanup, releases locks.
    std::process::exit(29);
}

#[test]
fn process_crash_releases_owner_and_drain_without_undoing_durable_denial() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let (_temp, root, store) = setup();
    store
        .add_selection(zero(), request(SearchProvider::Claude, "R", RootKind::Root))
        .unwrap();
    store
        .set_desired_updates(current(&store), DesiredUpdates::Paused)
        .unwrap();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "subprocess_revocation_owner", "--nocapture"])
            .env("ASG_TEST_REVOCATION_ROOT", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) if line.trim() == "revocation-durable" => {
                    let _ = ready_tx.send(());
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("child must durably deny before crash");
    let denied = store.status().unwrap();
    assert!(denied.policy.emission_blocked());
    assert!(!allowed(&denied.policy, SearchProvider::Claude, "R/F"));
    assert!(matches!(
        ExclusiveGuard::try_acquire(&root, LockKind::PolicyOwner),
        Err(PortError::WriterBusy(_))
    ));
    assert!(matches!(
        ExclusiveGuard::try_acquire(&root, LockKind::PolicyEmission),
        Err(PortError::WriterBusy(_))
    ));
    writeln!(child.0.stdin.take().unwrap(), "crash").unwrap();
    assert_eq!(child.0.wait().unwrap().code(), Some(29));
    reader.join().unwrap();
    let owner = exclusive_guard(&root, LockKind::PolicyOwner);
    let drained = exclusive_guard(&root, LockKind::PolicyEmission);
    store
        .settle_revocation(
            current(&store),
            &owner,
            &drained,
            &denied.policy.revocations[0].id,
            30,
        )
        .unwrap();
    let after = store.status().unwrap();
    assert!(!after.policy.emission_blocked());
    assert!(!allowed(&after.policy, SearchProvider::Claude, "R/F"));
    assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    assert_eq!(store.purge_jobs().unwrap()[0].state, PurgeState::Pending);
    assert!(!root.join("catalog.db").exists());
}

#[test]
fn live_runtime_load_is_bounded_but_keeps_exact_old_tokens_and_dependencies() {
    let (_temp, root, store, worker, selection) = worker_setup();
    set_catalog(&store, &worker, "catalog_a");
    let first = latest(&store, &selection, 1);
    let original = store
        .start_cycle(current(&store), &worker, first.required_cycle_seq, 2)
        .unwrap()
        .value;
    store
        .acknowledge_source(
            current(&store),
            &worker,
            source_ack(&original, &selection, true),
        )
        .unwrap();
    store
        .acknowledge_discovery(
            current(&store),
            &worker,
            DiscoveryAcknowledgement {
                token: original.token.clone(),
                selection: selection.clone(),
                complete: true,
                discovered_count: 1,
                observed_count: 1,
                committed_count: 1,
                error: None,
            },
        )
        .unwrap();
    let committed = store
        .finish_cycle(
            current(&store),
            &worker,
            original.token.cycle_seq,
            CycleFinish::Committed,
            3,
        )
        .unwrap()
        .value;

    // A large, valid old history tail is inserted without changing any evidence,
    // current source receipt, worker or admission semantics. It is deliberately
    // much larger than the reader's retained diagnostic tail.
    let raw_connection = raw(&root);
    let tx = raw_connection.unchecked_transaction().unwrap();
    let admitted = committed.admitted_control_seq.get();
    let started = committed.started_control_seq.unwrap().get();
    for cycle in 2..=2048 {
        tx.execute(
            "INSERT INTO cycles VALUES(?1,'boot_a',?2,'committed',?3,?4,2,3)",
            rusqlite::params![cycle, committed.policy_epoch.get(), admitted, started],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO cycle_selections VALUES(?1,?2,?3,1,?4,0,0,0,NULL)",
            rusqlite::params![
                cycle,
                selection.selection_id.as_str(),
                selection.revision.get(),
                selection.root_identity.as_str()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO barriers VALUES(?1,?2,?3,?4,'awaiting_catalog',1000,1,?4,NULL,NULL)",
            rusqlite::params![
                format!("old_barrier_{cycle:04}"),
                committed.policy_epoch.get(),
                admitted,
                cycle
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO barrier_selections VALUES(?1,?2,?3)",
            rusqlite::params![
                format!("old_barrier_{cycle:04}"),
                selection.selection_id.as_str(),
                selection.revision.get()
            ],
        )
        .unwrap();
    }
    tx.execute("UPDATE control_meta SET next_cycle_seq=2049", [])
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        store.background_status().unwrap().next_cycle_seq.get(),
        2049
    );
    assert_eq!(
        store
            .source_progress(&id("source_f"))
            .unwrap()
            .unwrap()
            .receipt
            .unwrap()
            .token,
        committed.token
    );
    assert_eq!(store.cycle(committed.token.cycle_seq).unwrap(), committed);
    assert_eq!(
        store.barrier(&first.id).unwrap().completed_cycle_seq,
        Some(committed.token.cycle_seq)
    );
    assert_eq!(
        store
            .barrier(&id("old_barrier_0010"))
            .unwrap()
            .required_cycle_seq
            .get(),
        10
    );
    assert_eq!(
        raw_connection
            .query_row("SELECT COUNT(*) FROM cycles", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2048
    );
    let reopened = SqliteControlStore::open_read_only(&root, &id("installation")).unwrap();
    assert_eq!(
        reopened
            .cycle(CycleSeq::new(10).unwrap())
            .unwrap()
            .token
            .cycle_seq
            .get(),
        10
    );

    // Current dependencies still use checked decoding rather than being hidden
    // by the historical read bound.
    raw_connection
        .execute(
            "UPDATE cycles SET started_control_seq=admitted_control_seq WHERE cycle_seq=1",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.background_status(),
        Err(PortError::SchemaIncompatible(_))
    ));
}
