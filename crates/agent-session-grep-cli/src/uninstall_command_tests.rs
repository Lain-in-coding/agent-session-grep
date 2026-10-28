//! Synthetic catalogs, profile settings and inert package images only. No host
//! process, production registry/service or provider history is modified.
use super::*;
use crate::setup_hosts::ExpectedAsgIdentity;
use agent_session_grep_adapters_sqlite::{SourceBatch, managed_locks::SharedGuard};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_launcher::{CurrentPointer, ReleaseMetadata, metadata, verify_installation};
use agent_session_grep_ports::{SearchProvider, control::*, managed::*};
use serde_json::json;
use std::cell::{Cell, RefCell};
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn lock(root: &Path, kind: LockKind) -> ExclusiveGuard {
    crate::retry_fixture_busy(|| ExclusiveGuard::try_acquire(root, kind.clone()))
}
fn control_status(control: &SqliteControlStore) -> ControlStatus {
    control
        .with_runtime_deadline(deadline(), || control.status())
        .unwrap()
}
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    prefix: PathBuf,
    catalog: PathBuf,
    source: PathBuf,
    control: SqliteControlStore,
    native_calls: RefCell<Vec<Vec<OsString>>>,
    path_calls: Cell<usize>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let root = base.join("data");
        let prefix = base.join("package");
        let source_dir = base.join("sources");
        fs::create_dir(&source_dir).unwrap();
        let source = source_dir.join("synthetic.jsonl");
        fs::write(
            &source,
            b"Synthetic original provider bytes remain untouched.\n",
        )
        .unwrap();
        let control = crate::retry_fixture_busy(|| {
            SqliteControlStore::create(
                &root,
                &id("uninstall-installation"),
                DesiredUpdates::Running,
            )
        });
        let catalog = root.join("catalog.db");
        let selected = control
            .add_selection(
                control_status(&control).policy.control_seq,
                SelectionRequest {
                    region: ScopeRegion {
                        provider: SearchProvider::Claude,
                        locator: CanonicalLocator::from_path(&source_dir).unwrap(),
                        kind: RootKind::Root,
                    },
                    root_identity: Some(id("synthetic-root")),
                    now_ms: 1,
                },
            )
            .unwrap()
            .value;
        let background = lock(&root, LockKind::Background);
        let worker = control
            .bind_worker(&background, id("synthetic-boot"))
            .unwrap();
        control
            .register_worker(control_status(&control).policy.control_seq, &worker, 1, 1)
            .unwrap();
        let cycle = match control
            .queue_cycle(
                control_status(&control).policy.control_seq,
                vec![SelectionRevision {
                    selection_id: selected.id.clone(),
                    revision: selected.revision,
                    root_identity: id("synthetic-root"),
                }],
            )
            .unwrap()
            .value
        {
            CycleAdmission::Queued(cycle) => cycle,
            other => panic!("unexpected fixture cycle {other:?}"),
        };
        let cycle = control
            .start_cycle(
                control_status(&control).policy.control_seq,
                &worker,
                cycle.token.cycle_seq,
                2,
            )
            .unwrap()
            .value;
        let store = ManagedStore::create(&catalog, &control, id("synthetic-catalog"), 1).unwrap();
        let session = StableId::native_checked(IdKind::Session, "synthetic-session").unwrap();
        let document = StableId::native_checked(IdKind::Document, "synthetic-document").unwrap();
        let message = StableId::native_checked(IdKind::Message, "synthetic-message").unwrap();
        let path = CanonicalLocator::from_path(&source)
            .unwrap()
            .as_str()
            .to_owned();
        let digest = "synthetic-document-digest";
        let batch = SourceBatch {
            source_path: path.clone(), entries: vec![
                (session.clone(), serde_json::to_vec(&json!({"documents":[document.as_str()]})).unwrap(), String::new()),
                (document.clone(), serde_json::to_vec(&json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":digest,"len":64})).unwrap(), String::new()),
                (message.clone(), serde_json::to_vec(&json!({"role":"user","text":"owned synthetic corpus needle","timestamp":null})).unwrap(), "owned synthetic corpus needle".into())],
            placements: vec![MessagePlacement::new(session, document, message, 0, false, None)],
            edges: vec![], activities: vec![], usage_events: vec![], relation_complete: true,
            len_bytes: Some(64), fingerprint: Some(digest.into()), provider_id: Some("claude-code".into()), resume_claims: vec![],
        };
        let observation = SourceObservation {
            binding: SourceBinding {
                source_id: SourceId::parse("synthetic-source").unwrap(),
                source_path: path,
                provider: SearchProvider::Claude,
                namespace_id: None,
                root_identity: "synthetic-root".into(),
            },
            revision_id: RevisionId::parse("synthetic-revision").unwrap(),
            revision_digest: digest.into(),
            parser_version: 1,
            state: ObservationState::Complete,
            cycle_seq: cycle.token.cycle_seq.get(),
            worker_boot_id: "synthetic-boot".into(),
            catalog_incarnation: "synthetic-catalog".into(),
            policy_epoch: cycle.policy_epoch.get(),
            started_control_seq: cycle.started_control_seq.unwrap().get(),
            observed_at_ms: 3,
            committed_at_ms: 4,
            selections: vec![SelectionProof {
                selection_id: selected.id.as_str().into(),
                selection_revision: selected.revision.get(),
                root_identity: "synthetic-root".into(),
            }],
            repositories: vec![],
        };
        store
            .commit_source(&control, &worker, &batch, &observation)
            .unwrap();
        store.reconcile_progress(&control, &worker).unwrap();
        drop(store);
        drop(worker);
        drop(background);
        let fixture = Self {
            _temp: temp,
            root,
            prefix,
            catalog,
            source,
            control,
            native_calls: RefCell::new(Vec::new()),
            path_calls: Cell::new(0),
        };
        drop(fixture.installation());
        let prefix_lock =
            update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
        let policy_lock = lock(&fixture.root, LockKind::PolicyOwner);
        let bound = fixture.control.bind_control_root(&policy_lock).unwrap();
        fixture
            .control
            .record_verified_installation_prefix(&fixture.prefix, &prefix_lock, &bound, deadline())
            .unwrap();
        fixture
            .control
            .set_desired_updates(
                control_status(&fixture.control).policy.control_seq,
                DesiredUpdates::Paused,
            )
            .unwrap();
        fixture
    }
    fn installation(&self) -> Installation {
        let content = b"inert immutable synthetic application, never executed";
        let digest = format!("{:x}", Sha256::digest(content));
        let directory = format!("versions/{}-{}", env!("CARGO_PKG_VERSION"), &digest[..12]);
        fs::create_dir_all(self.prefix.join(&directory)).unwrap();
        let app = self.prefix.join(&directory).join(metadata::APP_NAME);
        let supervisor = self.prefix.join(&directory).join(if cfg!(windows) {
            "asg-supervisor.exe"
        } else {
            "asg-supervisor"
        });
        if !app.exists() {
            write_private(&app, content);
        }
        if !supervisor.exists() {
            write_private(&supervisor, content);
        }
        let launcher = self.prefix.join(metadata::APP_NAME);
        if !launcher.exists() {
            write_private(&launcher, b"synthetic stable launcher");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&app, &supervisor] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let pointer = json!({"schema":"asg.current/v1","version":env!("CARGO_PKG_VERSION"),"generation":1,"dir":directory,"app":metadata::APP_NAME,"app_sha256":digest,"launcher_protocol":1,"activated_at":"2026-10-18T00:00:00Z"});
        let release = json!({"schema":"asg.version/v1","version":env!("CARGO_PKG_VERSION"),"target":metadata::BUILD_TARGET,"source_commit":"a".repeat(40),"app_sha256":digest,"catalog_schema":SCHEMA_VERSION,"control_schema":CONTROL_SCHEMA_VERSION,"launcher_protocol_min":1,"launcher_protocol_max":1,"built_at":"2026-10-18T00:00:00Z"});
        if !self.prefix.join("current.json").exists() {
            write_private(
                &self.prefix.join("current.json"),
                &serde_json::to_vec(&pointer).unwrap(),
            );
        }
        if !self.prefix.join(&directory).join("release.json").exists() {
            write_private(
                &self.prefix.join(&directory).join("release.json"),
                &serde_json::to_vec(&release).unwrap(),
            );
        }
        let pointer =
            CurrentPointer::parse(&fs::read(self.prefix.join("current.json")).unwrap()).unwrap();
        let release = ReleaseMetadata::parse(
            &fs::read(self.prefix.join(&directory).join("release.json")).unwrap(),
            &pointer,
        )
        .unwrap();
        Installation {
            prefix: self.prefix.clone(),
            pointer,
            release,
            package_files_sha256: String::new(),
            manifest_sha256: String::new(),
            archive_sha256: String::new(),
            helpers: BTreeMap::new(),
            launcher,
            expected: ExpectedAsgIdentity {
                version: env!("CARGO_PKG_VERSION").into(),
                launcher_sha256: digest.clone(),
            },
            supervisor: Some((supervisor, digest)),
            _application: verify_installation(&self.prefix).unwrap(),
            _guards: vec![],
            _metadata: vec![],
        }
    }
    fn execute(&self, keep_data: bool, until: Instant) -> Report {
        execute(
            self.catalog.to_str().unwrap(),
            Options {
                keep_data,
                prefix: Some(self.prefix.clone()),
            },
            until,
            &mut |_| Ok(self.installation()),
            &mut |_, args, _| {
                self.native_calls.borrow_mut().push(args.to_vec());
                Err(native_manager::ErrorCode::Unavailable.into())
            },
            &mut |_, _, _| {
                self.path_calls.set(self.path_calls.get() + 1);
                Ok(json!({"status":"complete","registration_present":false,"owned":true}))
            },
        )
        .unwrap()
    }
    fn journal(&self, keep_data: bool) -> Journal {
        let install = self.installation();
        let file = platform::open_file(&self.catalog).unwrap();
        let identity = platform::identity(&file).unwrap();
        drop(file);
        Journal::open(
            &install,
            &self.catalog,
            &self.control,
            keep_data,
            "synthetic-catalog".into(),
            identity,
            deadline(),
        )
        .unwrap()
    }
    fn fenced_journal(&self, keep_data: bool) -> Journal {
        let install_lock =
            update_state::acquire_installation_lock(&self.prefix, deadline()).unwrap();
        let installation = self
            .control
            .bind_installation(&self.prefix, &install_lock)
            .unwrap();
        let mut journal = self.journal(keep_data);
        fence(&self.control, &installation, &mut journal, deadline()).unwrap();
        journal.save(deadline()).unwrap();
        journal
    }
    fn preserved(&self) {
        assert_eq!(
            fs::read(&self.source).unwrap(),
            b"Synthetic original provider bytes remain untouched.\n"
        );
        assert_eq!(
            control_status(&self.control).desired_updates,
            DesiredUpdates::Paused
        );
    }
}
#[test]
fn uninstall_parser_rejects_ambiguous_unknown_and_repeated_arguments() {
    assert!(parse(&args(&["uninstall"])).is_ok());
    assert!(
        parse(&args(&[
            "uninstall",
            "--keep-data",
            "--install-prefix",
            "package"
        ]))
        .unwrap()
        .keep_data
    );
    for values in [
        vec!["remove"],
        vec!["uninstall", "--keep-data", "--keep-data"],
        vec!["uninstall", "--purge-settings"],
        vec!["uninstall", "--keep-data", "true"],
        vec!["uninstall", "--install-prefix"],
        vec!["uninstall", "--install-prefix", "--keep-data"],
        vec!["uninstall", "--install-prefix", "a/../b"],
        vec![
            "uninstall",
            "--install-prefix",
            "a",
            "--install-prefix",
            "b",
        ],
    ] {
        assert!(parse(&args(&values)).is_err(), "must reject {values:?}");
    }
}
#[test]
fn default_waits_for_live_control_handle_before_removing_catalog_or_control() {
    let fixture = Fixture::new();
    let report = fixture.execute(false, deadline());
    assert!(
        report.maintenance_fenced && report.catalog_drained && report.writer_drained,
        "actual stages: {}",
        serde_json::to_string(&report).unwrap()
    );
    assert!(!report.corpus_removed);
    assert!(report.reasons.iter().any(|reason| matches!(
        reason,
        Reason::ControlHandleDrainRequired | Reason::Deadline
    )));
    assert!(
        report.control_cleanup_pending && report.package_cleanup_pending && report.cleanup_pending
    );
    assert_eq!(report.outcome(), Outcome::Partial);
    assert!(fixture.catalog.exists());
    assert!(SqliteControlStore::path(&fixture.root).exists());
    assert!(!fixture.root.join(RETIREMENT_MARKER).exists());
    let deferred = read_deferred_cleanup(&fixture.prefix, &fixture.catalog, deadline())
        .unwrap()
        .unwrap();
    assert!(deferred.retirement_intent_captured && !deferred.control_retired);
    assert!(
        deferred
            .groups
            .iter()
            .any(|group| group.kind == GroupKind::Corpus && !group.removed)
    );
    assert_eq!(
        control_status(&fixture.control).policy.maintenance.state,
        MaintenanceState::Uninstalling
    );
    fixture.preserved();
}

#[test]
fn path_removal_runs_only_after_the_uninstalling_fence() {
    let fixture = Fixture::new();
    assert_eq!(
        control_status(&fixture.control).policy.maintenance.state,
        MaintenanceState::Idle
    );
    let report = execute(
        fixture.catalog.to_str().unwrap(),
        Options {
            keep_data: true,
            prefix: Some(fixture.prefix.clone()),
        },
        deadline(),
        &mut |_| Ok(fixture.installation()),
        &mut |_, _, _| Err(native_manager::ErrorCode::Unavailable.into()),
        &mut |_, _, _| {
            assert_eq!(
                control_status(&fixture.control).policy.maintenance.state,
                MaintenanceState::Uninstalling
            );
            Ok(json!({"status":"complete","registration_present":false,"owned":true}))
        },
    )
    .unwrap();
    assert!(report.maintenance_fenced);
    fixture.preserved();
}

#[test]
fn keep_data_keeps_catalog_policy_and_denies_without_clearing_pause() {
    let fixture = Fixture::new();
    let policy = control_status(&fixture.control).policy;
    let report = fixture.execute(true, deadline());
    assert!(
        !report.corpus_removed
            && report.catalog_and_policy_retained
            && report.continuation_cache_cleared
    );
    assert!(!report.control_cleanup_pending && report.package_cleanup_pending);
    assert!(fixture.catalog.exists());
    let after = control_status(&fixture.control);
    assert_eq!(after.policy.selections, policy.selections);
    assert_eq!(after.policy.exclusions, policy.exclusions);
    assert_eq!(after.policy.policy_epoch, policy.policy_epoch);
    fixture.preserved();
}
#[test]
fn live_catalog_handle_blocks_default_cleanup_with_durable_denial() {
    let fixture = Fixture::new();
    // The 300ms budget measures only the held reader gate, not Windows private
    // receipt setup under an unrelated full-suite filesystem load.
    let mut journal = fixture.fenced_journal(false);
    let installation =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    let operation = id(&journal.state.owner.nonce);
    let intent = RetirementIntent::bind(
        &fixture.control,
        &fixture.catalog,
        &fixture.prefix,
        &installation,
        &operation,
    )
    .unwrap();
    let holder = crate::retry_fixture_busy(|| {
        SharedGuard::try_acquire(&fixture.root, LockKind::CatalogHandles)
    });
    let before = fs::read(&fixture.catalog).unwrap();
    let started = Instant::now();
    assert!(
        cleanup_data(
            &fixture.control,
            &mut journal,
            Some(&intent),
            started + Duration::from_millis(300)
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(journal.state.report.maintenance_fenced && !journal.state.report.corpus_removed);
    assert_eq!(fs::read(&fixture.catalog).unwrap(), before);
    assert!(fixture.catalog.exists() && !fixture.root.join(RETIREMENT_MARKER).exists());
    drop(holder);
    fixture.preserved();
}
#[test]
fn repeated_private_receipt_never_switches_keep_data_to_default() {
    let fixture = Fixture::new();
    fixture.execute(true, deadline());
    let before = fs::read(&fixture.catalog).unwrap();
    assert!(
        execute(
            fixture.catalog.to_str().unwrap(),
            Options {
                keep_data: false,
                prefix: None
            },
            deadline(),
            &mut |_| Ok(fixture.installation()),
            &mut |_, _, _| Err(native_manager::ErrorCode::Unavailable.into()),
            &mut |_, _, _| panic!("no PATH effect after receipt mode conflict")
        )
        .is_err()
    );
    assert_eq!(fs::read(&fixture.catalog).unwrap(), before);
    fixture.preserved();
}
#[test]
fn file_changed_after_durable_plan_is_preserved() {
    let fixture = Fixture::new();
    let journal = fixture.fenced_journal(true);
    let policy = journal.validate(&fixture.control, deadline()).unwrap();
    let path = fixture.root.join("synthetic-owned-artifact.json");
    write_private(&path, b"owned initial image");
    let proof = owned_file(
        &fixture.root,
        "synthetic-owned-artifact.json",
        &policy,
        deadline(),
    )
    .unwrap();
    write_private(&path, b"independent changed image");
    assert_eq!(
        remove_file_checked(
            &fixture.root,
            &proof,
            &journal,
            &fixture.control,
            deadline()
        ),
        Err(Reason::FileChanged)
    );
    assert_eq!(fs::read(&path).unwrap(), b"independent changed image");
    fixture.preserved();
}
#[test]
fn verified_removal_never_deletes_an_unverified_replacement() {
    let fixture = Fixture::new();
    let journal = fixture.fenced_journal(true);
    let policy = journal.validate(&fixture.control, deadline()).unwrap();
    let path = fixture.root.join("synthetic-owned-artifact.json");
    write_private(&path, b"owned verified image");
    let proof = owned_file(
        &fixture.root,
        "synthetic-owned-artifact.json",
        &policy,
        deadline(),
    )
    .unwrap();
    let evidence = path.with_extension("evidence.json");
    fs::rename(&path, &evidence).unwrap();
    write_private(&path, b"independent replacement image");
    assert_eq!(
        verified_remove_file(&path, &proof.identity),
        Err(Reason::FileChanged)
    );
    assert_eq!(fs::read(&path).unwrap(), b"independent replacement image");
    assert_eq!(fs::read(&evidence).unwrap(), b"owned verified image");
    fs::remove_file(&evidence).unwrap();
    fixture.preserved();
}
#[cfg(windows)]
#[test]
fn verified_removal_deletes_the_exact_verified_handle() {
    let fixture = Fixture::new();
    let journal = fixture.fenced_journal(true);
    let policy = journal.validate(&fixture.control, deadline()).unwrap();
    let path = fixture.root.join("synthetic-owned-artifact.json");
    write_private(&path, b"owned verified image");
    let proof = owned_file(
        &fixture.root,
        "synthetic-owned-artifact.json",
        &policy,
        deadline(),
    )
    .unwrap();
    assert_eq!(verified_remove_file(&path, &proof.identity), Ok(()));
    assert!(!path.exists());
    fixture.preserved();
}
#[test]
fn source_selection_cannot_become_cleanup_authority_by_name() {
    let fixture = Fixture::new();
    let journal = fixture.fenced_journal(true);
    let policy = journal.validate(&fixture.control, deadline()).unwrap();
    let source_parent = fixture.source.parent().unwrap();
    assert!(matches!(
        owned_file(source_parent, "synthetic.jsonl", &policy, deadline()),
        Err(Reason::SourceOverlap)
    ));
    fixture.preserved();
}
#[test]
fn hardlinked_artifact_never_grants_delete_ownership() {
    let fixture = Fixture::new();
    let journal = fixture.fenced_journal(true);
    let path = fixture.root.join("owned-image.json");
    write_private(&path, b"shared bytes");
    fs::hard_link(
        &path,
        fixture
            .source
            .parent()
            .unwrap()
            .join("independent-hardlink.json"),
    )
    .unwrap();
    let policy = journal.validate(&fixture.control, deadline()).unwrap();
    assert!(matches!(
        owned_file(&fixture.root, "owned-image.json", &policy, deadline()),
        Err(Reason::FileChanged)
    ));
    assert_eq!(fs::read(&path).unwrap(), b"shared bytes");
    fixture.preserved();
}
#[cfg(unix)]
#[test]
fn symlinked_artifact_is_never_followed_for_cleanup() {
    let fixture = Fixture::new();
    let journal = fixture.fenced_journal(true);
    std::os::unix::fs::symlink(&fixture.source, fixture.root.join("symlink.json")).unwrap();
    let policy = journal.validate(&fixture.control, deadline()).unwrap();
    assert!(owned_file(&fixture.root, "symlink.json", &policy, deadline()).is_err());
    fixture.preserved();
}
#[cfg(windows)]
#[test]
fn windows_locked_file_leaves_pending_artifact_until_owner_releases() {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let journal = fixture.fenced_journal(true);
    let path = fixture.root.join("locked-artifact.json");
    write_private(&path, b"owned locked artifact");
    let policy = journal.validate(&fixture.control, deadline()).unwrap();
    let proof = owned_file(&fixture.root, "locked-artifact.json", &policy, deadline()).unwrap();
    let holder = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    assert_eq!(
        remove_file_checked(
            &fixture.root,
            &proof,
            &journal,
            &fixture.control,
            deadline()
        ),
        Err(Reason::FileLocked)
    );
    assert!(path.exists());
    drop(holder);
    remove_file_checked(
        &fixture.root,
        &proof,
        &journal,
        &fixture.control,
        deadline(),
    )
    .unwrap();
    assert!(!path.exists());
    fixture.preserved();
}
#[test]
fn new_inventory_binding_is_checked_and_legacy_remains_unclassified() {
    let fixture = Fixture::new();
    let journal = fixture.journal(true);
    let status = control_status(&fixture.control);
    let legacy: HostInventory = serde_json::from_value(json!({
        "schema":"asg.setup-host-inventory/v1", "receipts":[]
    }))
    .unwrap();
    assert_eq!(
        validate_inventory_binding(legacy.binding.as_ref(), &journal, &status),
        Err(Reason::UnclassifiedOwnedArtifact)
    );
    let mut value = json!({"schema":"asg.setup-inventory-binding/v1",
        "installation_id":status.policy.installation_id.as_str(),
        "control_root_id":journal.data_identity.control_id().as_str(),
        "created_policy_epoch":status.policy.policy_epoch.get()});
    let binding: InventoryBinding = serde_json::from_value(value.clone()).unwrap();
    assert!(validate_inventory_binding(Some(&binding), &journal, &status).is_ok());
    value["created_policy_epoch"] = json!(status.policy.policy_epoch.get() + 1);
    let binding: InventoryBinding = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        validate_inventory_binding(Some(&binding), &journal, &status),
        Err(Reason::UnclassifiedOwnedArtifact)
    );
    value["created_policy_epoch"] = json!(status.policy.policy_epoch.get());
    value["installation_id"] = json!("other-installation");
    let binding: InventoryBinding = serde_json::from_value(value).unwrap();
    assert_eq!(
        validate_inventory_binding(Some(&binding), &journal, &status),
        Err(Reason::UnclassifiedOwnedArtifact)
    );
}
#[test]
fn pending_purge_retains_keep_data_policy_jobs_and_catalog() {
    let fixture = Fixture::new();
    let selection = control_status(&fixture.control).policy.selections[0]
        .id
        .clone();
    let sequence = control_status(&fixture.control).policy.control_seq;
    fixture
        .control
        .revoke_selection(sequence, &selection, None, 50)
        .unwrap();
    let before = control_status(&fixture.control).policy;
    let jobs = fixture.control.purge_jobs().unwrap();
    let mut journal = fixture.fenced_journal(true);
    cleanup_data(&fixture.control, &mut journal, None, deadline()).unwrap();
    let after = control_status(&fixture.control).policy;
    assert_eq!(before.selections, after.selections);
    assert_eq!(before.exclusions, after.exclusions);
    assert_eq!(before.policy_epoch, after.policy_epoch);
    assert_eq!(jobs, fixture.control.purge_jobs().unwrap());
    assert!(fixture.catalog.exists());
    fixture.preserved();
}
#[test]
fn corrupt_private_journal_cannot_authorize_recovery_or_cleanup() {
    let fixture = Fixture::new();
    fixture.execute(true, deadline());
    let state = read_deferred_cleanup(&fixture.prefix, &fixture.catalog, deadline())
        .unwrap()
        .unwrap();
    let path = fixture
        .prefix
        .join("uninstall")
        .join(format!("state-{:06}.json", state.sequence));
    write_private(&path, b"corrupt private receipt");
    assert!(read_deferred_cleanup(&fixture.prefix, &fixture.catalog, deadline()).is_err());
    assert!(fixture.catalog.exists());
    fixture.preserved();
}

#[test]
fn default_closes_own_control_retires_and_removes_corpus_before_bounded_package_pending() {
    let fixture = Fixture::new();
    let install = fixture.installation();
    let Fixture {
        _temp,
        root,
        prefix,
        catalog,
        source,
        control,
        ..
    } = fixture;
    drop(control);
    let mut package = Some(install);
    let report = execute(
        catalog.to_str().unwrap(),
        Options {
            keep_data: false,
            prefix: Some(prefix.clone()),
        },
        Instant::now() + BUDGET,
        &mut |_| Ok(package.take().unwrap()),
        &mut |_, _, _| panic!("no native execution without an owned receipt"),
        &mut |_, _, _| Ok(json!({"status":"complete","registration_present":false})),
    )
    .unwrap();
    assert!(
        report.corpus_removed && report.continuation_cache_cleared,
        "actual stages: {}",
        serde_json::to_string(&report).unwrap()
    );
    assert!(!report.control_cleanup_pending);
    assert!(report.package_cleanup_pending && report.cleanup_pending);
    assert_eq!(report.outcome(), Outcome::Partial);
    assert!(!catalog.exists());
    assert!(!SqliteControlStore::path(&root).exists());
    assert!(root.join(RETIREMENT_MARKER).exists());
    assert!(SqliteControlStore::open_current_read_only(&root).is_err());
    assert!(prefix.join("current.json").exists());
    let state = read_deferred_cleanup(&prefix, &catalog, deadline())
        .unwrap()
        .unwrap();
    assert!(state.control_retired && state.retirement_intent_captured);
    assert!(
        state
            .groups
            .iter()
            .any(|group| group.kind == GroupKind::Control && group.removed)
    );
    assert_eq!(
        fs::read(source).unwrap(),
        b"Synthetic original provider bytes remain untouched.\n"
    );
    drop(_temp);
}
#[test]
fn retired_cleanup_resumes_without_reopening_control_or_catalog() {
    let fixture = Fixture::new();
    let install = fixture.installation();
    let mut journal = fixture.fenced_journal(false);
    journal.state.purge_prerequisite_complete = true;
    let installation_lock =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    let operation = id(&journal.state.owner.nonce);
    let intent = RetirementIntent::bind(
        &fixture.control,
        &fixture.catalog,
        &fixture.prefix,
        &installation_lock,
        &operation,
    )
    .unwrap();
    journal.state.retirement_intent_captured = true;
    let guards = cleanup_data(&fixture.control, &mut journal, Some(&intent), deadline()).unwrap();
    let intent = intent
        .refresh(&fixture.control, &guards.policy_owner)
        .unwrap();
    journal.save(deadline()).unwrap();
    let Fixture {
        _temp,
        root,
        prefix,
        catalog,
        source,
        control,
        ..
    } = fixture;
    drop(control);
    let retirement = intent.try_acquire(guards.retirement()).unwrap();
    retirement.publish_marker().unwrap();
    assert!(catalog.exists());
    assert!(SqliteControlStore::path(&root).exists());
    // Simulate the process ending immediately after durable marker publication.
    drop(retirement);
    drop(guards);
    drop(intent);
    drop(installation_lock);
    drop(journal);
    let report = resume_terminal(&install, &catalog, false, deadline()).unwrap();
    assert!(report.corpus_removed && !report.control_cleanup_pending);
    assert!(report.package_cleanup_pending && report.cleanup_pending);
    let again = resume_terminal(&install, &catalog, false, deadline()).unwrap();
    assert!(again.corpus_removed && !again.control_cleanup_pending);
    assert!(resume_terminal(&install, &catalog, true, deadline()).is_err());
    assert!(!catalog.exists() && !SqliteControlStore::path(&root).exists());
    assert!(root.join(RETIREMENT_MARKER).exists());
    assert!(
        read_deferred_cleanup(&prefix, &catalog, deadline())
            .unwrap()
            .unwrap()
            .control_retired
    );
    assert_eq!(
        fs::read(source).unwrap(),
        b"Synthetic original provider bytes remain untouched.\n"
    );
    drop(_temp);
}
#[test]
fn unexplained_control_rollback_journal_remains_private_and_pending() {
    let fixture = Fixture::new();
    let mut journal = fixture.fenced_journal(false);
    let install_lock =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    let operation = id(&journal.state.owner.nonce);
    let intent = RetirementIntent::bind(
        &fixture.control,
        &fixture.catalog,
        &fixture.prefix,
        &install_lock,
        &operation,
    )
    .unwrap();
    journal.state.retirement_intent_captured = true;
    let guards = cleanup_data(&fixture.control, &mut journal, Some(&intent), deadline()).unwrap();
    let intent = intent
        .refresh(&fixture.control, &guards.policy_owner)
        .unwrap();
    let Fixture {
        _temp,
        root,
        source,
        control,
        ..
    } = fixture;
    drop(control);
    let retirement = intent.try_acquire(guards.retirement()).unwrap();
    retirement.publish_marker().unwrap();
    write_private(
        &root.join("control.db-journal"),
        b"unexplained independently retained image",
    );
    assert!(matches!(
        terminal_control_plan(
            &journal,
            &retirement,
            journal.state.terminal_policy.as_ref().unwrap(),
            deadline()
        ),
        Err(Reason::ControlCleanupPending)
    ));
    assert!(SqliteControlStore::path(&root).exists());
    assert_eq!(
        fs::read(root.join("control.db-journal")).unwrap(),
        b"unexplained independently retained image"
    );
    assert_eq!(
        fs::read(source).unwrap(),
        b"Synthetic original provider bytes remain untouched.\n"
    );
    drop(retirement);
    drop(guards);
    drop(intent);
    drop(install_lock);
    drop(journal);
    drop(_temp);
}

#[test]
fn inventory_preserves_all_six_exact_serialized_host_ids() {
    for (host, serialized) in [
        (Host::ClaudeCode, "claude-code"),
        (Host::Codex, "codex"),
        (Host::ZCode, "zcode"),
        (Host::WorkBuddy, "workbuddy"),
        (Host::Antigravity, "antigravity"),
        (Host::DeepSeekHarness, "deepseek-harness"),
    ] {
        let record: HostInventory = serde_json::from_value(json!({
            "schema":"asg.setup-host-inventory/v1", "binding":null,
            "receipts":[{"host":serialized,"config_path":"synthetic/config",
                "transaction_root":"synthetic/transactions","transaction_id":"synthetic-transaction",
                "receipt_path":"synthetic/receipt.json"}]
        })).unwrap();
        assert_eq!(record.receipts[0].host, host);
        assert_eq!(
            serde_json::to_value(record.receipts[0].host).unwrap(),
            json!(serialized)
        );
    }
    assert!(serde_json::from_value::<Host>(json!("codebuddy")).is_err());
    assert!(serde_json::from_value::<Host>(json!("z-code")).is_err());
}
