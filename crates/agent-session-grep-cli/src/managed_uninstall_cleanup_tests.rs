//! Disposable package/private roots only. No production configuration or services.
use super::*;
use agent_session_grep_ports::control::{BackgroundControl, DesiredUpdates};
use serde_json::json;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BorrowedKeepDataCheck {
    Roots,
    Control,
    Catalog,
}
type BorrowedKeepDataHook = Box<dyn FnMut(BorrowedKeepDataCheck) -> Result<(), PortError>>;
type CompletionPassHook = Box<dyn FnMut(&mut Instant)>;
thread_local! {
    static BORROWED_KEEP_DATA_HOOK: RefCell<Option<BorrowedKeepDataHook>> = const { RefCell::new(None) };
    static COMPLETION_PASS_HOOK: RefCell<Option<CompletionPassHook>> = const { RefCell::new(None) };
}
pub(super) fn between_completion_passes(original: Instant) -> Instant {
    let mut end = original;
    COMPLETION_PASS_HOOK.with_borrow_mut(|slot| {
        if let Some(hook) = slot {
            hook(&mut end);
        }
    });
    assert!(
        end <= original,
        "completion fault cannot extend the original end"
    );
    end
}
fn with_completion_pass_hook<T>(
    hook: impl FnMut(&mut Instant) + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<CompletionPassHook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            COMPLETION_PASS_HOOK.with_borrow_mut(|slot| *slot = self.0.take());
        }
    }
    let _restore =
        Restore(COMPLETION_PASS_HOOK.with_borrow_mut(|slot| slot.replace(Box::new(hook))));
    operation()
}
pub(super) fn before_borrowed_keep_data_check(
    step: BorrowedKeepDataCheck,
) -> Result<(), PortError> {
    BORROWED_KEEP_DATA_HOOK.with_borrow_mut(|hook| match hook {
        Some(hook) => hook(step),
        None => Ok(()),
    })
}
fn with_borrowed_keep_data_hook<T>(
    hook: impl FnMut(BorrowedKeepDataCheck) -> Result<(), PortError> + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<BorrowedKeepDataHook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            BORROWED_KEEP_DATA_HOOK.with_borrow_mut(|hook| *hook = self.0.take());
        }
    }
    let _restore =
        Restore(BORROWED_KEEP_DATA_HOOK.with_borrow_mut(|slot| slot.replace(Box::new(hook))));
    operation()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn policy() -> TerminalPolicy {
    TerminalPolicy {
        control_seq: 0,
        policy_epoch: 0,
        regions: vec![],
        control_file_identity: (0, 0),
    }
}
fn private_root(path: &Path) {
    platform::create_private_directory(path).unwrap();
}
fn private_file(path: &Path, bytes: &[u8]) {
    update_state::write_new(path, bytes).unwrap();
}

#[test]
fn internal_parser_is_silent_and_rejects_unbounded_or_unknown_input() {
    assert_eq!(intercept(&[]), None);
    assert_eq!(intercept(&[OsString::from(CHILD)]), Some(2));
    assert_eq!(
        intercept(&[OsString::from(CHILD), OsString::from("--unknown")]),
        Some(2)
    );
    assert!(end_from_tick(0).is_err());
    assert!(end_from_tick(monotonic_ms().unwrap() + 100_000).is_err());
}
#[test]
fn exact_exit_lock_blocks_then_acquires_without_reading_another_windows_lock() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    private_root(&root);
    private_file(&root.join("exit.lock"), b"");
    let proof = private_proof(&root, "exit.lock", &policy(), deadline()).unwrap();
    let owner = exit_lock(&root, &proof, &policy(), deadline(), false).unwrap();
    let start = Instant::now();
    assert!(matches!(
        exit_lock(
            &root,
            &proof,
            &policy(),
            start + Duration::from_millis(75),
            true
        ),
        Err(Reason::Deadline)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(owner);
    let acquired = exit_lock(&root, &proof, &policy(), deadline(), true).unwrap();
    acquired
        .validate_current(&root, &proof, &policy(), deadline())
        .unwrap();
    assert!(matches!(
        exit_lock(&root, &proof, &policy(), deadline(), false),
        Err(Reason::AfterExitCleanupPending)
    ));
    drop(acquired);
    let reacquired = exit_lock(&root, &proof, &policy(), deadline(), false).unwrap();
    reacquired
        .validate_current(&root, &proof, &policy(), deadline())
        .unwrap();
}

#[test]
fn held_exit_guard_validation_requires_original_role_root_and_deadline() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    let other = temp.path().canonicalize().unwrap().join("other");
    private_root(&root);
    private_root(&other);
    for relative in ["parent-exit.lock", "runner-exit.lock"] {
        private_file(&root.join(relative), b"");
    }
    let parent = private_proof(&root, "parent-exit.lock", &policy(), deadline()).unwrap();
    let runner = private_proof(&root, "runner-exit.lock", &policy(), deadline()).unwrap();
    let guard = exit_lock(&root, &parent, &policy(), deadline(), false).unwrap();
    for _ in 0..3 {
        guard
            .validate_current(&root, &parent, &policy(), deadline())
            .unwrap();
        let contender = platform::open_file(&root.join(&parent.relative)).unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));
    }
    assert!(matches!(
        guard.validate_current(&root, &runner, &policy(), deadline()),
        Err(Reason::IdentityChanged)
    ));
    assert!(matches!(
        guard.validate_current(&other, &parent, &policy(), deadline()),
        Err(Reason::IdentityChanged)
    ));
    assert!(matches!(
        guard.validate_current(&root, &parent, &policy(), Instant::now()),
        Err(Reason::Deadline)
    ));
    assert_eq!(fs::read_dir(&other).unwrap().count(), 0);
    assert_eq!(fs::metadata(root.join(&parent.relative)).unwrap().len(), 0);
    drop(guard);
    let contender = platform::open_file(&root.join(&parent.relative)).unwrap();
    contender.try_lock().unwrap();
}

#[test]
fn held_exit_guard_validation_rejects_same_bytes_replacement_and_missing_name() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    private_root(&root);
    let path = root.join("parent-exit.lock");
    let old = root.join("original-lock");
    private_file(&path, b"");
    let proof = private_proof(&root, "parent-exit.lock", &policy(), deadline()).unwrap();
    let guard = exit_lock(&root, &proof, &policy(), deadline(), false).unwrap();
    match fs::rename(&path, &old) {
        Ok(()) => {}
        #[cfg(windows)]
        Err(error) => {
            assert!(matches!(error.raw_os_error(), Some(5 | 32 | 33)));
            guard
                .validate_current(&root, &proof, &policy(), deadline())
                .unwrap();
            return;
        }
        #[cfg(not(windows))]
        Err(error) => panic!("{error}"),
    }
    assert!(
        guard
            .validate_current(&root, &proof, &policy(), deadline())
            .is_err()
    );
    assert!(!path.exists());
    private_file(&path, b"");
    assert!(matches!(
        guard.validate_current(&root, &proof, &policy(), deadline()),
        Err(Reason::FileChanged)
    ));
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        guard
            .validate_current(&root, &proof, &policy(), deadline())
            .is_err()
    );
    assert!(path.is_dir() && old.exists());
}

#[cfg(unix)]
#[test]
fn held_exit_guard_validation_rejects_link_aliases() {
    use std::os::unix::fs::symlink;
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    private_root(&root);
    let path = root.join("parent-exit.lock");
    let old = root.join("original-lock");
    private_file(&path, b"");
    let proof = private_proof(&root, "parent-exit.lock", &policy(), deadline()).unwrap();
    let guard = exit_lock(&root, &proof, &policy(), deadline(), false).unwrap();
    fs::rename(&path, &old).unwrap();
    symlink(&old, &path).unwrap();
    assert!(
        guard
            .validate_current(&root, &proof, &policy(), deadline())
            .is_err()
    );
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_file(&path).unwrap();
    fs::hard_link(&old, &path).unwrap();
    assert!(
        guard
            .validate_current(&root, &proof, &policy(), deadline())
            .is_err()
    );
    assert_eq!(fs::metadata(&old).unwrap().len(), 0);
}
#[test]
fn replaced_empty_lock_inode_never_proves_original_owner_exit() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    private_root(&root);
    private_file(&root.join("exit.lock"), b"");
    let proof = private_proof(&root, "exit.lock", &policy(), deadline()).unwrap();
    let old = platform::open_file(&root.join("exit.lock")).unwrap();
    fs::rename(root.join("exit.lock"), root.join("original.lock")).unwrap();
    private_file(&root.join("exit.lock"), b"");
    assert!(matches!(
        exit_lock(&root, &proof, &policy(), deadline(), true),
        Err(Reason::FileChanged)
    ));
    assert_eq!(platform::identity(&old).unwrap(), proof.identity);
    assert!(root.join("original.lock").exists() && root.join("exit.lock").exists());
}
#[test]
fn finite_inventory_preserves_unknown_same_directory_and_provider_bytes() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    private_root(&root);
    private_root(&root.join("nested"));
    private_file(&root.join("nested/owned.json"), b"owned");
    let proof = private_proof(&root, "nested/owned.json", &policy(), deadline()).unwrap();
    assert!(account_tree(&root, std::slice::from_ref(&proof), &policy(), deadline()).unwrap());
    private_file(
        &root.join("nested/provider-history.jsonl"),
        b"unrelated original source bytes\n",
    );
    assert!(!account_tree(&root, &[proof], &policy(), deadline()).unwrap());
    assert_eq!(
        fs::read(root.join("nested/provider-history.jsonl")).unwrap(),
        b"unrelated original source bytes\n"
    );
}
#[test]
fn changed_and_hardlinked_files_do_not_gain_per_file_authority() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    private_root(&root);
    private_file(&root.join("payload"), b"original");
    let proof = private_proof(&root, "payload", &policy(), deadline()).unwrap();
    fs::write(root.join("payload"), b"modified").unwrap();
    assert!(matches!(
        verify(&root, &proof, &policy(), deadline(), false),
        Err(Reason::FileChanged)
    ));
    fs::hard_link(root.join("payload"), root.join("other-link")).unwrap();
    assert!(private_proof(&root, "payload", &policy(), deadline()).is_err());
    assert_eq!(fs::read(root.join("other-link")).unwrap(), b"modified");
}
#[test]
fn source_region_even_with_owned_name_never_grants_cleanup_authority() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    private_root(&root);
    private_file(&root.join("owned.log"), b"source bytes");
    let mut selected = policy();
    selected.regions.push(TerminalRegion {
        locator: CanonicalLocator::from_path(&root).unwrap().as_str().into(),
        recursive: true,
    });
    assert!(matches!(
        private_proof(&root, "owned.log", &selected, deadline()),
        Err(Reason::SourceOverlap)
    ));
}
#[test]
fn transfer_tick_keeps_original_budget_and_rejects_reboot_or_reset_value() {
    let end = Instant::now() + Duration::from_millis(150);
    let tick = deadline_tick(end).unwrap();
    let child_end = end_from_tick(tick).unwrap();
    assert!(child_end <= end + Duration::from_millis(2));
    assert!(end_from_tick(tick + BUDGET.as_millis() as u64).is_err());
    assert!(end_from_tick(monotonic_ms().unwrap().saturating_sub(1)).is_err());
}

struct PackageFixture {
    prefix: PathBuf,
    root: PathBuf,
    catalog: PathBuf,
    control: Option<SqliteControlStore>,
    members: BTreeMap<String, (Vec<u8>, String)>,
    // Connections and OS guards must close before Windows temp cleanup.
    _temp: tempfile::TempDir,
}
impl PackageFixture {
    fn new(tail: bool) -> Self {
        Self::with_application(
            tail,
            b"inert synthetic native application, never executed".to_vec(),
        )
    }

    fn with_application(tail: bool, app: Vec<u8>) -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let prefix = base.join("package");
        let root = base.join("data");
        private_root(&prefix);
        let control = crate::retry_fixture_busy(|| {
            SqliteControlStore::create(
                &root,
                &id("synthetic-uninstall-installation"),
                DesiredUpdates::Paused,
            )
        });
        let catalog = root.join("catalog.db");
        // Setup control calls share one explicit end. Without a caller scope,
        // each call receives only the short implicit busy allowance.
        control
            .with_runtime_deadline(deadline(), || {
                let store =
                    ManagedStore::create(&catalog, &control, id("synthetic-uninstall-catalog"), 1)?;
                let worker_lock = acquire(
                    &root,
                    LockKind::Background,
                    deadline(),
                    Reason::BackgroundDrainPending,
                )
                .unwrap();
                let worker = control.bind_worker(&worker_lock, id("synthetic-worker-boot"))?;
                control.register_worker(control.status()?.policy.control_seq, &worker, 1, 1)?;
                store.reconcile_progress(&control, &worker)?;
                drop(worker);
                drop(worker_lock);
                drop(store);
                Ok(())
            })
            .unwrap();
        let installation_lock =
            update_state::acquire_installation_lock(&prefix, deadline()).unwrap();
        let policy_owner = acquire(
            &root,
            LockKind::PolicyOwner,
            deadline(),
            Reason::IdentityChanged,
        )
        .unwrap();
        {
            let bound = control.bind_control_root(&policy_owner).unwrap();
            control
                .record_verified_installation_prefix(
                    &prefix,
                    &installation_lock,
                    &bound,
                    deadline(),
                )
                .unwrap();
        }
        drop(policy_owner);
        drop(installation_lock);
        let launcher = b"inert synthetic stable launcher".to_vec();
        let digest = format!("{:x}", Sha256::digest(&app));
        let dir = format!("versions/{}-{}", env!("CARGO_PKG_VERSION"), &digest[..12]);
        fs::create_dir(prefix.join("versions")).unwrap();
        private_root(&prefix.join(&dir));
        private_root(&prefix.join(&dir).join("helpers"));
        let mut members = BTreeMap::new();
        let app_name = agent_session_grep_launcher::metadata::APP_NAME;
        let alias = if cfg!(windows) { "asg.exe" } else { "asg" };
        let supervisor = if cfg!(windows) {
            "asg-supervisor.exe"
        } else {
            "asg-supervisor"
        };
        members.insert(app_name.into(), (launcher.clone(), "0755".into()));
        members.insert(alias.into(), (launcher, "0755".into()));
        members.insert(format!("{dir}/{app_name}"), (app, "0755".into()));
        members.insert(
            format!("{dir}/{supervisor}"),
            (b"inert synthetic supervisor".to_vec(), "0755".into()),
        );
        let version = env!("CARGO_PKG_VERSION");
        members.insert("current.json".into(), (serde_json::to_vec(&json!({"schema":"asg.current/v1","version":version,"generation":1,"dir":dir,"app":app_name,"app_sha256":digest,"launcher_protocol":1,"activated_at":"2026-10-18T00:00:00Z"})).unwrap(), "0644".into()));
        members.insert(format!("{dir}/release.json"), (serde_json::to_vec(&json!({"schema":"asg.version/v1","version":version,"target":agent_session_grep_launcher::metadata::BUILD_TARGET,"source_commit":"a".repeat(40),"app_sha256":digest,"catalog_schema":SCHEMA_VERSION,"control_schema":CONTROL_SCHEMA_VERSION,"launcher_protocol_min":1,"launcher_protocol_max":1,"built_at":"2026-10-18T00:00:00Z"})).unwrap(), "0644".into()));
        for name in [
            "package-install.ps1",
            "package-install.sh",
            "INSTALL-AND-UPGRADE.md",
            "README.md",
            "CHANGELOG.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "NOTICE",
            "SECURITY.md",
            "THIRD-PARTY-DEPENDENCIES.json",
            "THIRD-PARTY-DEPENDENCIES.csv",
        ] {
            members.insert(
                name.into(),
                (format!("synthetic {name}\n").into_bytes(), "0644".into()),
            );
        }
        for name in ["update-check.sh", "update-check.ps1"] {
            members.insert(
                format!("{dir}/helpers/{name}"),
                (format!("synthetic {name}").into_bytes(), "0644".into()),
            );
        }
        if tail {
            members.insert(
                format!("{dir}/helpers/{WINDOWS_TAIL_HELPER}"),
                (
                    include_bytes!("../../../scripts/install/package-uninstall.ps1").to_vec(),
                    "0644".into(),
                ),
            );
        }
        for (name, (bytes, mode)) in &members {
            private_file(&prefix.join(name), bytes);
            // Match the installed package mode: the verifier requires every
            // execute bit, and the launcher refuses a non-executable app
            // before cleanup ever reads the package plan.
            #[cfg(unix)]
            if mode == "0755" {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(prefix.join(name), fs::Permissions::from_mode(0o755)).unwrap();
            }
            #[cfg(not(unix))]
            let _ = mode;
        }
        let fields = [
            ("version", version.into()),
            (
                "target",
                agent_session_grep_launcher::metadata::BUILD_TARGET.into(),
            ),
            ("source_commit", "a".repeat(40)),
            ("app", app_name.into()),
            ("app_sha256", digest.clone()),
            ("dir", dir),
            ("supervisor", supervisor.into()),
            (
                "supervisor_sha256",
                format!("{:x}", Sha256::digest(b"inert synthetic supervisor")),
            ),
            ("launcher_protocol", "1".into()),
            ("catalog_schema", SCHEMA_VERSION.to_string()),
            ("control_schema", CONTROL_SCHEMA_VERSION.to_string()),
            ("built_at", "2026-10-18T00:00:00Z".into()),
        ];
        let mut manifest = String::from("asg.package-files/v1\n");
        for (name, value) in fields {
            manifest.push_str(&format!("{name}\t{value}\n"));
        }
        for (name, (bytes, mode)) in &members {
            manifest.push_str(&format!(
                "file\t{:x}\t{mode}\t{}\t{name}\n",
                Sha256::digest(bytes),
                bytes.len()
            ));
        }
        private_file(&prefix.join("PACKAGE-MANIFEST.tsv"), manifest.as_bytes());
        private_file(
            &prefix.join("package-install.json"),
            b"synthetic receipt owned by fixture verify seam",
        );
        Self {
            _temp: temp,
            prefix,
            root,
            catalog,
            control: Some(control),
            members,
        }
    }
    fn install(&self) -> Installation {
        let pointer = agent_session_grep_launcher::CurrentPointer::parse(
            &fs::read(self.prefix.join("current.json")).unwrap(),
        )
        .unwrap();
        let release = agent_session_grep_launcher::ReleaseMetadata::parse(
            &fs::read(self.prefix.join(&pointer.dir).join("release.json")).unwrap(),
            &pointer,
        )
        .unwrap();
        let mut helpers = BTreeMap::new();
        for (relative, (bytes, _)) in &self.members {
            if let Some(name) = relative.strip_prefix(&format!("{}/helpers/", pointer.dir)) {
                helpers.insert(
                    name.into(),
                    package_installation::InstalledHelper {
                        path: self.prefix.join(relative),
                        sha256: format!("{:x}", Sha256::digest(bytes)),
                    },
                );
            }
        }
        Installation {
            prefix: self.prefix.clone(),
            pointer,
            release,
            package_files_sha256: format!(
                "{:x}",
                Sha256::digest(fs::read(self.prefix.join("PACKAGE-MANIFEST.tsv")).unwrap())
            ),
            manifest_sha256: String::new(),
            archive_sha256: String::new(),
            helpers,
            launcher: self
                .prefix
                .join(agent_session_grep_launcher::metadata::APP_NAME),
            expected: setup_hosts::ExpectedAsgIdentity {
                version: env!("CARGO_PKG_VERSION").into(),
                launcher_sha256: format!(
                    "{:x}",
                    Sha256::digest(b"inert synthetic stable launcher")
                ),
            },
            supervisor: None,
            _application: agent_session_grep_launcher::verify_installation(&self.prefix).unwrap(),
            _guards: vec![],
            _metadata: vec![],
        }
    }
    fn journal(&self, keep: bool) -> (Installation, Journal) {
        let install = self.install();
        let control = self.control.as_ref().unwrap();
        let catalog_file_identity =
            platform::identity(&platform::open_file(&self.catalog).unwrap()).unwrap();
        let mut journal = Journal::open(
            &install,
            &self.catalog,
            control,
            keep,
            "synthetic-uninstall-catalog".into(),
            catalog_file_identity,
            deadline(),
        )
        .unwrap();
        journal.state.package_files =
            package_plan(&install, &journal, control, deadline()).unwrap();
        journal.save(deadline()).unwrap();
        let install_lock =
            update_state::acquire_installation_lock(&self.prefix, deadline()).unwrap();
        // Each independent preparation request keeps one explicit end.
        // Tail execution and cleanup retain their own original budgets.
        let installation = control
            .with_runtime_deadline(deadline(), || {
                control.bind_installation(&self.prefix, &install_lock)
            })
            .unwrap();
        journal.state.purge_prerequisite_complete = true;
        fence(control, &installation, &mut journal, deadline()).unwrap();
        journal.save(deadline()).unwrap();
        let path = remove_path_current(&UninstallPathAuthority {
            journal: &journal,
            control,
            install: &install,
            prefix_guard: &install_lock,
            installation: &installation,
            root: &self.root,
            end: deadline(),
        })
        .unwrap();
        assert_eq!(path["reason"], "unowned");
        assert_eq!(path["installation_bound"], true);
        journal.state.report.path = Some(path);
        journal.save(deadline()).unwrap();
        journal.state.private_metadata =
            classify_private(&install, control, &journal, deadline()).unwrap();
        if keep {
            let guards = cleanup_data(control, &mut journal, None, deadline()).unwrap();
            drop(guards);
        } else {
            let operation = id(&journal.state.owner.nonce);
            let intent = RetirementIntent::bind_with_deadline(
                control,
                &self.catalog,
                &self.prefix,
                &install_lock,
                &operation,
                deadline(),
            )
            .unwrap();
            journal.state.retirement_intent_captured = true;
            let guards = cleanup_data(control, &mut journal, Some(&intent), deadline()).unwrap();
            let _ = intent
                .refresh_with_deadline(control, &guards.policy_owner, deadline())
                .unwrap();
            drop(guards);
        }
        journal.save(deadline()).unwrap();
        prepare(&install, &mut journal, deadline()).unwrap();
        (install, journal)
    }
}

// Retain the full synthetic inventory and durable bytes. Locked rendezvous
// bytes are read only through their held handles; SQLite owns transient SHM
// bookkeeping, so neither is compared through a second pathname read.
fn borrowed_keep_data_inventory(fixture: &PackageFixture) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    cleanup_inventory(&fixture.prefix, &fixture.root)
}

fn cleanup_inventory(prefix: &Path, data: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn collect(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if meta.is_dir() {
                out.insert(relative, None);
                collect(root, &path, out);
            } else {
                assert!(meta.is_file());
                let name = path.file_name().unwrap().to_str().unwrap();
                let bytes = if name.ends_with(".lock") || name.ends_with("-shm") {
                    None
                } else {
                    Some(fs::read(&path).unwrap())
                };
                out.insert(relative, bytes);
            }
        }
    }
    let mut out = BTreeMap::new();
    let root = prefix.parent().unwrap();
    collect(root, prefix, &mut out);
    collect(root, data, &mut out);
    out
}

#[test]
fn terminal_regions_preserves_disabled_selections_and_locator_denials_in_order() {
    use agent_session_grep_ports::{
        SearchProvider,
        control::{Exclusion, ScopeRegion, Selection},
    };

    let fixture = PackageFixture::new(false);
    let control = fixture.control.as_ref().unwrap();
    let mut policy = control
        .with_runtime_deadline(deadline(), || control.lifecycle_status())
        .unwrap()
        .policy;
    let selected = CanonicalLocator::from_path(&fixture.root.join("selected")).unwrap();
    let disabled = CanonicalLocator::from_path(&fixture.root.join("disabled.jsonl")).unwrap();
    let denied = CanonicalLocator::from_path(&fixture.root.join("denied")).unwrap();
    for (name, locator, kind, enabled) in [
        ("selected", selected.clone(), RootKind::Root, true),
        ("disabled", disabled.clone(), RootKind::Exact, false),
    ] {
        policy.selections.push(Selection {
            id: id(name),
            region: ScopeRegion {
                provider: SearchProvider::Codex,
                locator,
                kind,
            },
            root_identity: None,
            enabled,
            revision: policy.control_seq,
            created_at_ms: 1,
            revoked_at_ms: (!enabled).then_some(2),
        });
    }
    for (name, region) in [
        (
            "denied-locator",
            ExcludedRegion::Locator(ScopeRegion {
                provider: SearchProvider::Codex,
                locator: denied.clone(),
                kind: RootKind::Root,
            }),
        ),
        (
            "denied-identity",
            ExcludedRegion::SourceIdentity {
                provider: SearchProvider::Codex,
                source_id: id("synthetic-denied-source"),
            },
        ),
    ] {
        policy.exclusions.push(Exclusion {
            id: id(name),
            region,
            revision: policy.control_seq,
            created_policy_epoch: policy.policy_epoch,
            created_at_ms: 1,
        });
    }
    let before = policy.clone();
    let expected = json!([
        {"locator": selected.as_str(), "recursive": true},
        {"locator": disabled.as_str(), "recursive": false},
        {"locator": denied.as_str(), "recursive": true},
    ]);
    assert_eq!(
        serde_json::to_value(terminal_regions(&policy)).unwrap(),
        expected
    );
    assert_eq!(
        serde_json::to_value(
            TerminalPolicy::capture(&policy, &fixture.root)
                .unwrap()
                .regions
        )
        .unwrap(),
        expected
    );
    assert_eq!(policy, before);
}

#[test]
fn borrowed_keep_data_matches_the_seal_without_reopening_or_changing_inventory() {
    use crate::uninstall_command::tests::{ControlValidationRead, with_control_validation_hook};
    use std::cell::Cell;

    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let control = fixture.control.as_ref().unwrap();
    let seal = read_seal(&journal, deadline()).unwrap();
    let preparation_end = deadline();
    let prefix_lock =
        update_state::acquire_installation_lock(&fixture.prefix, preparation_end).unwrap();
    let installation = control
        .with_runtime_deadline(preparation_end, || {
            control.bind_installation(&fixture.prefix, &prefix_lock)
        })
        .unwrap();
    let mut guards = drain_owners(&mut journal, preparation_end).unwrap();
    let writer_before = guards._writer.read_record().unwrap();
    let before = borrowed_keep_data_inventory(&fixture);
    let state_before = serde_json::to_vec(&journal.state).unwrap();
    let status_before = control
        .with_runtime_deadline(deadline(), || control.lifecycle_status())
        .unwrap();
    let opens = Rc::new(Cell::new(0));
    let observed = Rc::clone(&opens);
    with_control_validation_hook(
        move |step| {
            if step == ControlValidationRead::Open {
                observed.set(observed.get() + 1);
                Err(PortError::Backend(
                    "synthetic control reopen refused".into(),
                ))
            } else {
                Ok(())
            }
        },
        || {
            // Positive control: the existing reopening path really is blocked.
            assert!(matches!(
                journal.validate(control, deadline()),
                Err(Reason::IdentityChanged)
            ));
            assert_eq!(opens.get(), 1);
            for _ in 0..3 {
                validate_borrowed_keep_data(
                    &journal,
                    &seal,
                    control,
                    &installation,
                    &guards,
                    deadline(),
                )
                .unwrap();
            }
            assert_eq!(opens.get(), 1);
        },
    );
    assert!(matches!(
        ExclusiveGuard::try_acquire(&fixture.root, LockKind::PolicyOwner),
        Err(PortError::WriterBusy(_))
    ));
    assert!(matches!(
        ExclusiveGuard::try_acquire(
            &fixture.prefix,
            LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY).unwrap())
        ),
        Err(PortError::WriterBusy(_))
    ));
    assert!(matches!(
        WriterLease::try_acquire(&fixture.root),
        Err(PortError::WriterBusy(_))
    ));
    assert_eq!(guards._writer.read_record().unwrap(), writer_before);
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
    assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state_before);
    assert_eq!(
        control
            .with_runtime_deadline(deadline(), || control.lifecycle_status())
            .unwrap(),
        status_before
    );
    drop(guards);
    let contender = ExclusiveGuard::try_acquire(&fixture.root, LockKind::PolicyOwner).unwrap();
    drop(contender);
}

#[test]
fn borrowed_keep_data_refuses_each_fence_and_seal_mismatch_without_effects() {
    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let control = fixture.control.as_ref().unwrap();
    let seal = read_seal(&journal, deadline()).unwrap();
    let preparation_end = deadline();
    let prefix_lock =
        update_state::acquire_installation_lock(&fixture.prefix, preparation_end).unwrap();
    let installation = control
        .with_runtime_deadline(preparation_end, || {
            control.bind_installation(&fixture.prefix, &prefix_lock)
        })
        .unwrap();
    let guards = drain_owners(&mut journal, preparation_end).unwrap();
    let original_state = journal.state.clone();
    let original_seal = serde_json::to_vec(&seal).unwrap();
    let owner_path = journal.root.join("owner.json");
    let original_owner = fs::read(&owner_path).unwrap();
    let status_before = control
        .with_runtime_deadline(deadline(), || control.lifecycle_status())
        .unwrap();
    for case in [
        "nonce",
        "installation",
        "incarnation",
        "sequence",
        "epoch",
        "regions",
        "mode",
    ] {
        journal.state = original_state.clone();
        let mut candidate: Seal = serde_json::from_slice(&original_seal).unwrap();
        match case {
            "nonce" => journal.state.owner.nonce = "synthetic-other-uninstall".into(),
            "installation" => {
                journal.state.owner.installation_id = "synthetic-other-installation".into();
            }
            "incarnation" => {
                journal.state.catalog_incarnation = "synthetic-other-catalog".into();
                candidate.catalog_incarnation = journal.state.catalog_incarnation.clone();
            }
            "sequence" => candidate.policy.control_seq += 1,
            "epoch" => candidate.policy.policy_epoch += 1,
            "regions" => candidate.policy.regions.push(TerminalRegion {
                locator: CanonicalLocator::from_path(&fixture.root.join("synthetic-region"))
                    .unwrap()
                    .as_str()
                    .into(),
                recursive: true,
            }),
            "mode" => journal.state.owner.keep_data = false,
            _ => unreachable!(),
        }
        // Keep the forged journal/owner/seal coherent, so nonce/installation
        // refusal must compare with the actual connection's lifecycle snapshot.
        candidate.owner = journal.state.owner.clone();
        fs::write(
            &owner_path,
            serde_json::to_vec(&journal.state.owner).unwrap(),
        )
        .unwrap();
        let before = borrowed_keep_data_inventory(&fixture);
        let state_before = serde_json::to_vec(&journal.state).unwrap();
        assert!(
            matches!(
                validate_borrowed_keep_data(
                    &journal,
                    &candidate,
                    control,
                    &installation,
                    &guards,
                    deadline()
                ),
                Err(Reason::MaintenanceConflict)
            ),
            "{case}"
        );
        assert_eq!(borrowed_keep_data_inventory(&fixture), before, "{case}");
        assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state_before);
        assert_eq!(
            control
                .with_runtime_deadline(deadline(), || control.lifecycle_status())
                .unwrap(),
            status_before
        );
    }
    fs::write(owner_path, original_owner).unwrap();
    journal.state = original_state;
    validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline())
        .unwrap();

    // Keep the owner and counters coherent with a real non-uninstall fence.
    // Only the required maintenance state may explain this refusal.
    let bound = control.bind_control_root(&guards.policy_owner).unwrap();
    let owner = id(&journal.state.owner.nonce);
    let status = control
        .with_runtime_deadline(deadline(), || {
            let status = control.lifecycle_status()?;
            control.begin_maintenance(
                status.policy.control_seq,
                &owner,
                &bound,
                &installation,
                MaintenanceFence {
                    state: MaintenanceState::Updating,
                    owner: Some(owner.clone()),
                    phase: Some(MaintenancePhase::Quiescing),
                },
            )?;
            control.lifecycle_status()
        })
        .unwrap();
    let mut candidate: Seal = serde_json::from_slice(&original_seal).unwrap();
    candidate.policy.control_seq = status.policy.control_seq.get();
    candidate.policy.policy_epoch = status.policy.policy_epoch.get();
    let before = borrowed_keep_data_inventory(&fixture);
    assert!(matches!(
        validate_borrowed_keep_data(
            &journal,
            &candidate,
            control,
            &installation,
            &guards,
            deadline()
        ),
        Err(Reason::MaintenanceConflict)
    ));
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
    assert_eq!(
        control
            .with_runtime_deadline(deadline(), || control.lifecycle_status())
            .unwrap(),
        status
    );
}

#[test]
fn borrowed_keep_data_refuses_foreign_guards_and_changed_prefix_receipt() {
    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let control = fixture.control.as_ref().unwrap();
    let seal = read_seal(&journal, deadline()).unwrap();
    let preparation_end = deadline();
    let prefix_lock =
        update_state::acquire_installation_lock(&fixture.prefix, preparation_end).unwrap();
    let installation = control
        .with_runtime_deadline(preparation_end, || {
            control.bind_installation(&fixture.prefix, &prefix_lock)
        })
        .unwrap();
    let mut guards = drain_owners(&mut journal, preparation_end).unwrap();
    let other = PackageFixture::new(false);
    let other_control = other.control.as_ref().unwrap();
    let other_end = deadline();
    let other_prefix_lock =
        update_state::acquire_installation_lock(&other.prefix, other_end).unwrap();
    let other_installation = other_control
        .with_runtime_deadline(other_end, || {
            other_control.bind_installation(&other.prefix, &other_prefix_lock)
        })
        .unwrap();
    let before = borrowed_keep_data_inventory(&fixture);
    assert!(matches!(
        validate_borrowed_keep_data(
            &journal,
            &seal,
            control,
            &other_installation,
            &guards,
            deadline()
        ),
        Err(Reason::IdentityChanged)
    ));
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
    for wrong_owner in [
        ExclusiveGuard::try_acquire(&other.root, LockKind::PolicyOwner).unwrap(),
        ExclusiveGuard::try_acquire(&fixture.root, LockKind::HistoryReaders).unwrap(),
    ] {
        let original = std::mem::replace(&mut guards.policy_owner, wrong_owner);
        let before = borrowed_keep_data_inventory(&fixture);
        assert!(matches!(
            validate_borrowed_keep_data(
                &journal,
                &seal,
                control,
                &installation,
                &guards,
                deadline()
            ),
            Err(Reason::IdentityChanged)
        ));
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        drop(std::mem::replace(&mut guards.policy_owner, original));
    }
    let binding = fixture.root.join("installation-prefix.json");
    let original_binding = fs::read(&binding).unwrap();
    fs::write(&binding, b"{}").unwrap();
    let before = borrowed_keep_data_inventory(&fixture);
    assert!(matches!(
        validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline()),
        Err(Reason::IdentityChanged)
    ));
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
    fs::write(binding, original_binding).unwrap();
    validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline())
        .unwrap();
}

#[test]
fn borrowed_keep_data_refuses_same_byte_catalog_replacement() {
    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let control = fixture.control.as_ref().unwrap();
    let seal = read_seal(&journal, deadline()).unwrap();
    let preparation_end = deadline();
    let prefix_lock =
        update_state::acquire_installation_lock(&fixture.prefix, preparation_end).unwrap();
    let installation = control
        .with_runtime_deadline(preparation_end, || {
            control.bind_installation(&fixture.prefix, &prefix_lock)
        })
        .unwrap();
    let guards = drain_owners(&mut journal, preparation_end).unwrap();
    let bytes = fs::read(&fixture.catalog).unwrap();
    let original = fixture.root.join("original-catalog");
    fs::rename(&fixture.catalog, &original).unwrap();
    let before_missing = borrowed_keep_data_inventory(&fixture);
    assert!(matches!(
        validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline()),
        Err(Reason::CorpusCleanupPending)
    ));
    assert_eq!(borrowed_keep_data_inventory(&fixture), before_missing);
    private_file(&fixture.catalog, &bytes);
    assert_ne!(
        platform::identity(&platform::open_file(&fixture.catalog).unwrap()).unwrap(),
        journal.state.catalog_file_identity
    );
    let before_replaced = borrowed_keep_data_inventory(&fixture);
    assert!(matches!(
        validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline()),
        Err(Reason::IdentityChanged)
    ));
    assert_eq!(borrowed_keep_data_inventory(&fixture), before_replaced);
    fs::remove_file(&fixture.catalog).unwrap();
    fs::rename(original, &fixture.catalog).unwrap();
    validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline())
        .unwrap();
}

#[test]
fn borrowed_keep_data_refuses_reopened_control_with_the_old_seal() {
    let mut fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let mut seal = read_seal(&journal, deadline()).unwrap();
    let preparation_end = deadline();
    let prefix_lock =
        update_state::acquire_installation_lock(&fixture.prefix, preparation_end).unwrap();
    let control = fixture.control.as_ref().unwrap();
    let installation = control
        .with_runtime_deadline(preparation_end, || {
            control.bind_installation(&fixture.prefix, &prefix_lock)
        })
        .unwrap();
    let guards = drain_owners(&mut journal, preparation_end).unwrap();
    let status_before = control
        .with_runtime_deadline(deadline(), || control.lifecycle_status())
        .unwrap();
    drop(fixture.control.take());
    let path = SqliteControlStore::path(&fixture.root);
    let bytes = fs::read(&path).unwrap();
    fs::rename(&path, fixture.root.join("original-control")).unwrap();
    private_file(&path, &bytes);
    let replaced = platform::identity(&platform::open_file(&path).unwrap()).unwrap();
    assert_ne!(replaced, seal.policy.control_file_identity);
    let reopened =
        SqliteControlStore::open_current_read_only_with_deadline(&fixture.root, deadline())
            .unwrap();
    assert_eq!(
        reopened
            .with_runtime_deadline(deadline(), || reopened.lifecycle_status())
            .unwrap(),
        status_before
    );
    let before = borrowed_keep_data_inventory(&fixture);
    assert!(matches!(
        validate_borrowed_keep_data(
            &journal,
            &seal,
            &reopened,
            &installation,
            &guards,
            deadline()
        ),
        Err(Reason::IdentityChanged)
    ));
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
    seal.policy.control_file_identity = replaced;
    validate_borrowed_keep_data(
        &journal,
        &seal,
        &reopened,
        &installation,
        &guards,
        deadline(),
    )
    .unwrap();
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
}

#[test]
fn borrowed_keep_data_restores_the_outer_scope_after_success_error_and_unwind() {
    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let control = fixture.control.as_ref().unwrap();
    let seal = read_seal(&journal, deadline()).unwrap();
    let preparation_end = deadline();
    let prefix_lock =
        update_state::acquire_installation_lock(&fixture.prefix, preparation_end).unwrap();
    let installation = control
        .with_runtime_deadline(preparation_end, || {
            control.bind_installation(&fixture.prefix, &prefix_lock)
        })
        .unwrap();
    let guards = drain_owners(&mut journal, preparation_end).unwrap();
    let before = borrowed_keep_data_inventory(&fixture);
    let end = deadline();
    let outer = end + Duration::from_secs(10);
    let probe = outer + Duration::from_secs(10);
    let observed = Rc::new(RefCell::new(Vec::new()));
    let calls = Rc::clone(&observed);
    control
        .with_runtime_deadline(outer, || {
            with_borrowed_keep_data_hook(
                move |step| {
                    calls
                        .borrow_mut()
                        .push((step, SqliteControlStore::effective_runtime_deadline(probe)));
                    Ok(())
                },
                || {
                    validate_borrowed_keep_data(
                        &journal,
                        &seal,
                        control,
                        &installation,
                        &guards,
                        end,
                    )
                    .unwrap();
                },
            );
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
            with_borrowed_keep_data_hook(
                move |step| {
                    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), end);
                    if step == BorrowedKeepDataCheck::Control {
                        Err(PortError::WriterBusy("synthetic bounded contention".into()))
                    } else {
                        Ok(())
                    }
                },
                || {
                    assert!(matches!(
                        validate_borrowed_keep_data(
                            &journal,
                            &seal,
                            control,
                            &installation,
                            &guards,
                            end
                        ),
                        Err(Reason::ControlCleanupPending)
                    ));
                },
            );
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_borrowed_keep_data_hook(
                    |step| {
                        if step == BorrowedKeepDataCheck::Catalog {
                            panic!("synthetic borrowed inspection unwind");
                        }
                        Ok(())
                    },
                    || {
                        let _ = validate_borrowed_keep_data(
                            &journal,
                            &seal,
                            control,
                            &installation,
                            &guards,
                            end,
                        );
                    },
                );
            }));
            assert!(unwound.is_err());
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
            control.lifecycle_status()?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        *observed.borrow(),
        [
            (BorrowedKeepDataCheck::Roots, end),
            (BorrowedKeepDataCheck::Control, end),
            (BorrowedKeepDataCheck::Catalog, end),
        ]
    );
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline())
        .unwrap();
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
}

#[test]
fn borrowed_keep_data_expiry_uses_the_earliest_end_and_skips_later_checks() {
    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let control = fixture.control.as_ref().unwrap();
    let seal = read_seal(&journal, deadline()).unwrap();
    let preparation_end = deadline();
    let prefix_lock =
        update_state::acquire_installation_lock(&fixture.prefix, preparation_end).unwrap();
    let installation = control
        .with_runtime_deadline(preparation_end, || {
            control.bind_installation(&fixture.prefix, &prefix_lock)
        })
        .unwrap();
    let guards = drain_owners(&mut journal, preparation_end).unwrap();
    let before = borrowed_keep_data_inventory(&fixture);
    with_borrowed_keep_data_hook(
        |_| panic!("expired entry must not inspect roots, control or catalog"),
        || {
            assert!(matches!(
                validate_borrowed_keep_data(
                    &journal,
                    &seal,
                    control,
                    &installation,
                    &guards,
                    Instant::now()
                ),
                Err(Reason::Deadline)
            ));
        },
    );
    let outer = Instant::now() + Duration::from_secs(2);
    let requested = outer + Duration::from_secs(10);
    let observed = Rc::new(RefCell::new(Vec::new()));
    let calls = Rc::clone(&observed);
    let result = control.with_runtime_deadline(outer, || {
        with_borrowed_keep_data_hook(
            move |step| {
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(requested),
                    outer
                );
                calls.borrow_mut().push(step);
                if step == BorrowedKeepDataCheck::Control {
                    std::thread::sleep(
                        outer.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                    );
                }
                Ok(())
            },
            || {
                // Binding/the adapter now returns real deadline contention.
                // Mapping against the later request would report pending.
                assert!(matches!(
                    validate_borrowed_keep_data(
                        &journal,
                        &seal,
                        control,
                        &installation,
                        &guards,
                        requested
                    ),
                    Err(Reason::Deadline)
                ));
            },
        );
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(requested),
            outer
        );
        with_borrowed_keep_data_hook(
            |_| panic!("expired outer scope must refuse before any inspection"),
            || {
                assert!(matches!(
                    validate_borrowed_keep_data(
                        &journal,
                        &seal,
                        control,
                        &installation,
                        &guards,
                        requested
                    ),
                    Err(Reason::Deadline)
                ));
            },
        );
        Ok(())
    });
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    assert_eq!(
        *observed.borrow(),
        [BorrowedKeepDataCheck::Roots, BorrowedKeepDataCheck::Control]
    );
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(requested),
        requested
    );
    validate_borrowed_keep_data(&journal, &seal, control, &installation, &guards, deadline())
        .unwrap();
    assert_eq!(borrowed_keep_data_inventory(&fixture), before);
}

/// Prepare real cleanup ownership while leaving package/runner completion pending.
/// Default cleanup uses the real terminal capability during preparation only.
fn package_fixture_for_finalize(keep: bool) -> (PackageFixture, Journal) {
    let mut fixture = PackageFixture::new(cfg!(windows));
    let (install, mut journal) = fixture.journal(keep);
    drop(install);
    if !keep {
        let control = fixture.control.take().unwrap();
        let prefix = update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
        let operation = id(&journal.state.owner.nonce);
        let intent = RetirementIntent::bind_with_deadline(
            &control,
            &fixture.catalog,
            &fixture.prefix,
            &prefix,
            &operation,
            deadline(),
        )
        .unwrap();
        let cleanup = cleanup_data(&control, &mut journal, Some(&intent), deadline()).unwrap();
        let intent = intent
            .refresh_with_deadline(&control, &cleanup.policy_owner, deadline())
            .unwrap();
        drop(control);
        terminal_handoff(&mut journal, &intent, cleanup.retirement(), deadline()).unwrap();
    }
    (fixture, journal)
}

#[test]
fn pending_path_blocks_existing_helper_plan_before_prepare_or_finalize_effects() {
    for keep in [false, true] {
        let (fixture, mut journal) = package_fixture_for_finalize(keep);
        let seal = read_seal(&journal, deadline()).unwrap();
        let parent = exit_lock(
            &journal.root,
            &seal.parent_exit,
            &seal.policy,
            deadline(),
            false,
        )
        .unwrap();
        let runner = exit_lock(
            &journal.root,
            &seal.runner_exit,
            &seal.policy,
            deadline(),
            false,
        )
        .unwrap();
        let installation =
            update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
        for path in [
            json!({"status": "incomplete", "reason": "recovery_required", "installation_bound": true}),
            json!({"status": "complete", "registration_present": false, "installation_bound": true}),
        ] {
            journal.state.report.path = Some(path);
            journal
                .state
                .report
                .pending(Reason::PathConfigurationRetained);
            journal.save(deadline()).unwrap();
            let before = borrowed_keep_data_inventory(&fixture);
            let (result, drains) = crate::uninstall_command::tests::observe_drain_calls(|| {
                finalize(
                    &mut journal,
                    &seal,
                    &installation,
                    &parent,
                    &runner,
                    deadline(),
                )
            });
            assert_eq!(result, Err(Reason::PathConfigurationRetained));
            assert_eq!(drains, 0);
            assert_eq!(borrowed_keep_data_inventory(&fixture), before);
            let install = fixture.install();
            assert_eq!(
                prepare(&install, &mut journal, deadline()),
                Err(Reason::PathConfigurationRetained)
            );
            assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        }
    }
}

const RUNNER_GATE_ENTRY: &str =
    "uninstall_command::managed_uninstall_cleanup::tests::pending_path_real_runner_process_helper";
const RUNNER_GATE_ENV: &str = "ASG_TEST_PENDING_PATH_RUNNER";
const RUNNER_GATE_ACK: &str = "asg.pending-path-real-runner/v1";
const RUNNER_GATE_RESULT: &str = "asg.pending-path-real-runner-result/v1 ";
const RUNNER_GATE_IO_LIMIT: usize = 16 * 1024;
#[cfg(windows)]
const RUNNER_JOB_CONTROL_ENTRY: &str = "uninstall_command::managed_uninstall_cleanup::tests::pending_path_runner_job_empty_process_helper";
#[cfg(windows)]
const RUNNER_JOB_CONTROL_ACK: &str = "asg.runner-job-empty-control/v1";

#[derive(Clone, Copy, Debug)]
enum RunnerGateSubject {
    PendingPath,
    ActivationInputs,
    #[cfg(windows)]
    EmptyControl,
}

impl RunnerGateSubject {
    fn entry(self) -> &'static str {
        match self {
            Self::PendingPath => RUNNER_GATE_ENTRY,
            Self::ActivationInputs => {
                "uninstall_command::managed_uninstall_cleanup::managed_reinstall_handoff::tests::activation_inputs_process_helper"
            }
            #[cfg(windows)]
            Self::EmptyControl => RUNNER_JOB_CONTROL_ENTRY,
        }
    }

    fn ack(self) -> &'static str {
        match self {
            Self::PendingPath => RUNNER_GATE_ACK,
            Self::ActivationInputs => "asg.activation-inputs-retained/v1",
            #[cfg(windows)]
            Self::EmptyControl => RUNNER_JOB_CONTROL_ACK,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerGateRequest {
    prefix: PathBuf,
    catalog: PathBuf,
    nonce: String,
    tick: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerGateResult {
    reason: Option<Reason>,
    after_image_authority: usize,
    before_tail_consumption: usize,
    end_observed: bool,
    within_end: bool,
}

#[derive(Default)]
struct RunnerGateObservation {
    end: Option<Instant>,
    after_image_authority: usize,
    before_tail_consumption: usize,
}

thread_local! {
    static RUNNER_GATE_OBSERVATION: RefCell<Option<RunnerGateObservation>> = const { RefCell::new(None) };
}

pub(super) fn observe_runner_admission(event: RunnerAdmissionEvent, end: Instant) {
    RUNNER_GATE_OBSERVATION.with_borrow_mut(|slot| {
        let Some(observed) = slot else {
            return;
        };
        if let Some(original) = observed.end {
            assert_eq!(end, original, "runner admission renewed its end");
        } else {
            observed.end = Some(end);
        }
        match event {
            RunnerAdmissionEvent::AfterImageAuthority => observed.after_image_authority += 1,
            RunnerAdmissionEvent::BeforeTailConsumption => {
                observed.before_tail_consumption += 1;
                // Fail before a broken gate could consume a receipt or spawn a
                // Windows tail. This assertion never substitutes a return value.
                panic!("pending PATH reached tail consumption");
            }
        }
    });
}

#[test]
fn pending_path_real_runner_process_helper() {
    // Normal suite discovery does not run the child body. Only the exact
    // copied libtest image receives this marker and the bounded stdin request.
    if std::env::var_os(RUNNER_GATE_ENV).as_deref() != Some(OsStr::new("1")) {
        return;
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((RUNNER_GATE_IO_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= RUNNER_GATE_IO_LIMIT);
    let request: RunnerGateRequest = serde_json::from_slice(&bytes).unwrap();
    let running = std::env::current_exe().unwrap();
    let runner = request
        .prefix
        .join("uninstall/helper")
        .join(if cfg!(windows) {
            "runner.exe"
        } else {
            "runner"
        });
    assert!(
        running.canonicalize().unwrap() == runner.canonicalize().unwrap(),
        "child must execute the actual prepared runner"
    );
    assert!(monotonic_ms().unwrap() < request.tick);
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            RUNNER_GATE_OBSERVATION.with_borrow_mut(|slot| *slot = None);
        }
    }
    RUNNER_GATE_OBSERVATION.with_borrow_mut(|slot| {
        assert!(slot.is_none());
        *slot = Some(RunnerGateObservation::default());
    });
    let restore = Restore;
    // The caller supplies one original recovery end. PATH must refuse before
    // recovery can even replace the historical tick in the in-memory plan.
    let result = run_child(
        &request.prefix,
        &request.catalog,
        &request.nonce,
        request.tick,
        true,
    );
    let observed = RUNNER_GATE_OBSERVATION.with_borrow_mut(|slot| slot.take().unwrap());
    drop(restore);
    // Only fixed enums/counts leave this child. Emit before assertions so a
    // refusal cannot be hidden by the parent's later Job accounting assertion.
    println!(
        "\n{RUNNER_GATE_RESULT}{}",
        serde_json::to_string(&RunnerGateResult {
            reason: result.err(),
            after_image_authority: observed.after_image_authority,
            before_tail_consumption: observed.before_tail_consumption,
            end_observed: observed.end.is_some(),
            within_end: monotonic_ms().is_ok_and(|now| now < request.tick),
        })
        .unwrap()
    );
    assert_eq!(result, Err(Reason::PathConfigurationRetained));
    assert_eq!(observed.after_image_authority, 1);
    assert_eq!(observed.before_tail_consumption, 0);
    assert!(observed.end.is_some());
    assert!(monotonic_ms().unwrap() < request.tick);
    println!("\n{RUNNER_GATE_ACK}");
}

#[cfg(windows)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerJobControlRequest {
    tick: u64,
}

#[cfg(windows)]
#[test]
fn pending_path_runner_job_empty_process_helper() {
    if std::env::var_os(RUNNER_GATE_ENV).as_deref() != Some(OsStr::new("1")) {
        return;
    }
    // This independent control has no package, journal, SQLite, run_child or
    // tail call. The same libtest process waits for the same post-assignment
    // stdin release, acknowledges only this empty body, then exits naturally.
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((RUNNER_GATE_IO_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= RUNNER_GATE_IO_LIMIT);
    let request: RunnerJobControlRequest = serde_json::from_slice(&bytes).unwrap();
    assert!(monotonic_ms().unwrap() < request.tick);
    println!("\n{RUNNER_JOB_CONTROL_ACK}");
}

#[cfg(windows)]
#[test]
fn pending_path_runner_job_empty_child_has_one_process() {
    // Execute the same built image directly, without creating another package
    // or copying a fixture. Its result cannot discharge the PATH test's gate.
    let image = std::env::current_exe().unwrap();
    let end = deadline();
    let request = RunnerJobControlRequest {
        tick: deadline_tick(end).unwrap(),
    };
    call_runner_gate_child(
        &image,
        image.parent().unwrap(),
        serde_json::to_vec(&request).unwrap(),
        request.tick,
        end,
        RunnerGateSubject::EmptyControl,
    );
}

#[derive(PartialEq, Eq)]
enum RunnerGateInput {
    Directory((u64, u64)),
    File {
        identity: (u64, u64),
        size: u64,
        digest: Option<String>,
    },
}

fn runner_gate_inventory(fixture: &PackageFixture) -> BTreeMap<PathBuf, RunnerGateInput> {
    fn collect(
        base: &Path,
        path: &Path,
        end: Instant,
        entries: &mut BTreeMap<PathBuf, RunnerGateInput>,
    ) {
        time(end).unwrap();
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        let relative = path.strip_prefix(base).unwrap().to_path_buf();
        let node = if metadata.is_dir() {
            let identity = platform::identity(&platform::directory(path).unwrap()).unwrap();
            for entry in fs::read_dir(path).unwrap() {
                collect(base, &entry.unwrap().path(), end, entries);
            }
            RunnerGateInput::Directory(identity)
        } else {
            assert!(metadata.is_file());
            let name = path.file_name().unwrap().to_str().unwrap();
            if name.ends_with(".lock") || name.ends_with("-shm") {
                // Lock contents and SQLite-owned SHM are not byte oracles.
                RunnerGateInput::File {
                    identity: platform::identity(&platform::open_file(path).unwrap()).unwrap(),
                    size: metadata.len(),
                    digest: None,
                }
            } else {
                let name = relative.to_str().unwrap().replace('\\', "/");
                let proof = private_proof(base, &name, &policy(), end).unwrap();
                RunnerGateInput::File {
                    identity: proof.identity,
                    size: proof.size,
                    digest: Some(proof.digest),
                }
            }
        };
        assert!(entries.insert(relative, node).is_none());
    }
    let end = deadline();
    let mut entries = BTreeMap::new();
    let base = fixture.prefix.parent().unwrap();
    collect(base, &fixture.prefix, end, &mut entries);
    collect(base, &fixture.root, end, &mut entries);
    entries
}

#[cfg(windows)]
struct RunnerGateJob(std::os::windows::io::OwnedHandle);

#[cfg(windows)]
#[derive(Debug)]
struct RunnerGateJobAccounting {
    total: u32,
    active: u32,
    limit_terminated: u32,
}

#[cfg(windows)]
#[derive(Debug)]
struct RunnerGateJobProbe {
    accounting: RunnerGateJobAccounting,
    listed: u32,
    owned_listed: bool,
    other_count: usize,
    owned_in_job: bool,
    owned_in_any_job: bool,
}

#[cfg(windows)]
impl RunnerGateJobProbe {
    fn empty_before_assignment(&self) -> bool {
        self.accounting.total == 0
            && self.accounting.active == 0
            && self.accounting.limit_terminated == 0
            && self.listed == 0
            && !self.owned_listed
            && self.other_count == 0
            && !self.owned_in_job
    }

    fn only_owned_child(&self) -> bool {
        self.accounting.active == 1
            && self.accounting.limit_terminated == 0
            && self.listed == 1
            && self.owned_listed
            && self.other_count == 0
            && self.owned_in_job
            && self.owned_in_any_job
    }

    fn empty_after_exit(&self) -> bool {
        self.accounting.active == 0
            && self.accounting.limit_terminated == 0
            && self.listed == 0
            && !self.owned_listed
            && self.other_count == 0
    }
}

#[cfg(windows)]
impl RunnerGateJob {
    fn new() -> Self {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::JobObjects::*;
        // A private, noninheritable Job is kept until the directly owned child
        // exits. Admission through stdin starts only after assignment succeeds.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        assert!(!raw.is_null(), "runner Job creation failed");
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle() as _,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            },
            0,
            "runner Job policy failed"
        );
        job
    }

    fn assign(&self, child: &std::process::Child) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        assert_ne!(
            unsafe {
                AssignProcessToJobObject(self.0.as_raw_handle() as _, child.as_raw_handle() as _)
            },
            0,
            "runner Job assignment failed"
        );
    }

    fn accounting(&self) -> Result<RunnerGateJobAccounting, &'static str> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::*;
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle() as _,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("query_failed");
        }
        Ok(RunnerGateJobAccounting {
            total: accounting.TotalProcesses,
            active: accounting.ActiveProcesses,
            limit_terminated: accounting.TotalTerminatedProcesses,
        })
    }

    fn probe(
        &self,
        child: &std::process::Child,
        end: Instant,
    ) -> Result<RunnerGateJobProbe, &'static str> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::{
            JobObjects::{IsProcessInJob, JobObjectBasicProcessIdList, QueryInformationJobObject},
            Threading::GetProcessId,
        };
        if Instant::now() >= end {
            return Err("probe_expired");
        }
        let accounting = self.accounting()?;
        // Read this retained Job only. Fixed scratch fails closed on truncation;
        // PID values are compared here and never stored in diagnostic output.
        #[repr(C)]
        struct Processes {
            assigned: u32,
            returned: u32,
            ids: [usize; 8],
        }
        let mut processes = Processes {
            assigned: 0,
            returned: 0,
            ids: [0; 8],
        };
        let mut bytes = 0;
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle() as _,
                JobObjectBasicProcessIdList,
                (&mut processes as *mut Processes).cast(),
                std::mem::size_of_val(&processes) as u32,
                &mut bytes,
            )
        } == 0
            || processes.assigned != processes.returned
            || processes.returned as usize > processes.ids.len()
            || bytes as usize > std::mem::size_of_val(&processes)
            || (bytes as usize)
                < 2 * std::mem::size_of::<u32>()
                    + processes.returned as usize * std::mem::size_of::<usize>()
        {
            return Err("pid_list_incomplete");
        }
        let owned_id = unsafe { GetProcessId(child.as_raw_handle() as _) };
        if owned_id == 0 || owned_id != child.id() {
            return Err("owned_handle_mismatch");
        }
        let mut owned_in_job = 0;
        let mut owned_in_any_job = 0;
        if unsafe {
            IsProcessInJob(
                child.as_raw_handle() as _,
                self.0.as_raw_handle() as _,
                &mut owned_in_job,
            )
        } == 0
            || unsafe {
                IsProcessInJob(
                    child.as_raw_handle() as _,
                    std::ptr::null_mut(),
                    &mut owned_in_any_job,
                )
            } == 0
        {
            return Err("membership_query_failed");
        }
        let ids = &processes.ids[..processes.returned as usize];
        Ok(RunnerGateJobProbe {
            accounting,
            listed: processes.returned,
            owned_listed: ids.contains(&(owned_id as usize)),
            other_count: ids.iter().filter(|id| **id != owned_id as usize).count(),
            owned_in_job: owned_in_job != 0,
            owned_in_any_job: owned_in_any_job != 0,
        })
    }

    fn observe_empty(&self, end: Instant) -> Result<RunnerGateJobAccounting, &'static str> {
        loop {
            let accounting = self.accounting()?;
            // TotalProcesses also counts associations refused by a Job limit.
            // Preserve all three counters; do not infer a running descendant
            // or relax the original total==1 oracle from that fact.
            if accounting.active == 0 || Instant::now() >= end {
                return Ok(accounting);
            }
            std::thread::sleep(
                Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
            );
        }
    }
}

struct RunnerGateChild {
    child: std::process::Child,
    end: Instant,
    #[cfg(windows)]
    job: RunnerGateJob,
}

impl Drop for RunnerGateChild {
    fn drop(&mut self) {
        if self.child.try_wait().is_ok_and(|status| status.is_some()) {
            return;
        }
        // This is the retained Child, never a PID/name search or process tree
        // guessed from the machine. A failed test must still reap its runner.
        let _termination = self.child.kill();
        while Instant::now() < self.end {
            if self.child.try_wait().is_ok_and(|status| status.is_some()) {
                return;
            }
            std::thread::sleep(
                Duration::from_millis(5).min(self.end.saturating_duration_since(Instant::now())),
            );
        }
        // Never unwind into TempDir deletion while the owned runner might still
        // be alive. Aborting this failing libtest process retains its fixture;
        // on Windows the noninheritable Job closes and terminates its member.
        eprintln!("pending PATH runner did not reap within its original end");
        std::process::abort();
    }
}

fn read_runner_gate_output(mut input: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut overflow = false;
    let mut buffer = [0; 4096];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            return Ok((kept, overflow));
        }
        let retain = count.min(RUNNER_GATE_IO_LIMIT - kept.len());
        kept.extend_from_slice(&buffer[..retain]);
        overflow |= retain != count;
    }
}

fn call_pending_path_runner(runner: &Path, request: &RunnerGateRequest, end: Instant) {
    call_runner_gate_child(
        runner,
        &request.prefix,
        serde_json::to_vec(request).unwrap(),
        request.tick,
        end,
        RunnerGateSubject::PendingPath,
    );
}

pub(super) fn call_activation_inputs_child(directory: &Path, input: Vec<u8>, end: Instant) {
    let tick = monotonic_ms()
        .unwrap()
        .checked_add(end.saturating_duration_since(Instant::now()).as_millis() as u64)
        .unwrap();
    call_runner_gate_child(
        &std::env::current_exe().unwrap(),
        directory,
        input,
        tick,
        end,
        RunnerGateSubject::ActivationInputs,
    );
}

fn call_runner_gate_child(
    runner: &Path,
    directory: &Path,
    input: Vec<u8>,
    tick: u64,
    end: Instant,
    subject: RunnerGateSubject,
) {
    use std::process::{Command, Stdio};
    assert!(input.len() <= RUNNER_GATE_IO_LIMIT);
    let mut command = Command::new(runner);
    command
        .args([
            "--exact",
            subject.entry(),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RUNNER_GATE_ENV, "1")
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    let job = {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW can create a hidden conhost in this Job. This
        // pipe-only test needs no console; DETACHED_PROCESS keeps the strict
        // one-process oracle while all standard handles remain explicit.
        command.creation_flags(0x00000008);
        RunnerGateJob::new()
    };
    let work_end = end - Duration::from_secs(2);
    assert!(
        Instant::now() < work_end,
        "runner admission has no cleanup reserve"
    );
    std::thread::scope(|scope| {
        let mut owned = RunnerGateChild {
            child: command.spawn().expect("prepared runner spawn failed"),
            end,
            #[cfg(windows)]
            job,
        };
        #[cfg(windows)]
        let job_before = owned.job.probe(&owned.child, end);
        #[cfg(windows)]
        owned.job.assign(&owned.child);
        #[cfg(windows)]
        let job_admitted = owned.job.probe(&owned.child, end);
        // The child is still waiting for stdin in both snapshots above.
        let stdout = owned.child.stdout.take().unwrap();
        let stderr = owned.child.stderr.take().unwrap();
        let stdout = scope.spawn(move || read_runner_gate_output(stdout));
        let stderr = scope.spawn(move || read_runner_gate_output(stderr));
        let mut stdin = owned.child.stdin.take().unwrap();
        let stdin = scope.spawn(move || stdin.write_all(&input));
        let status = loop {
            if let Some(status) = owned.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < work_end,
                "pending PATH runner exhausted its work window"
            );
            std::thread::sleep(
                Duration::from_millis(5).min(work_end.saturating_duration_since(Instant::now())),
            );
        };
        #[cfg(windows)]
        let job_accounting = owned.job.observe_empty(end);
        #[cfg(windows)]
        let job_after = owned.job.probe(&owned.child, end);
        #[cfg(windows)]
        let job_ok = job_accounting.as_ref().is_ok_and(|value| {
            value.total == 1 && value.active == 0 && value.limit_terminated == 0
        }) && job_before
            .as_ref()
            .is_ok_and(RunnerGateJobProbe::empty_before_assignment)
            && job_admitted
                .as_ref()
                .is_ok_and(RunnerGateJobProbe::only_owned_child)
            && job_after
                .as_ref()
                .is_ok_and(RunnerGateJobProbe::empty_after_exit);
        #[cfg(not(windows))]
        let (job_accounting, job_before, job_admitted, job_after, job_ok) = ((), (), (), (), true);
        // The exact child was reaped above. Close its retained handle and Job
        // before joining pipes, including on a failed accounting observation.
        drop(owned);
        while !stdin.is_finished() || !stdout.is_finished() || !stderr.is_finished() {
            if Instant::now() >= end {
                eprintln!(
                    "runner output did not drain: subject={subject:?} status={:?} job={job_accounting:?} \
                     before={job_before:?} admitted={job_admitted:?} after={job_after:?}",
                    status.code()
                );
                // Do not unwind into fixture deletion or an unbounded scoped
                // thread join while an owned pipe is still live.
                std::process::abort();
            }
            std::thread::sleep(
                Duration::from_millis(5).min(end.saturating_duration_since(Instant::now())),
            );
        }
        let stdin_ok = matches!(stdin.join(), Ok(Ok(())));
        let (stdout, stdout_overflow, stdout_ok) = match stdout.join() {
            Ok(Ok((bytes, overflow))) => (bytes, overflow, true),
            _ => (Vec::new(), false, false),
        };
        let (stderr, stderr_overflow, stderr_ok) = match stderr.join() {
            Ok(Ok((bytes, overflow))) => (bytes, overflow, true),
            _ => (Vec::new(), false, false),
        };
        let text = std::str::from_utf8(&stdout).ok();
        let ack = text.map_or(0, |text| {
            text.lines().filter(|line| *line == subject.ack()).count()
        });
        let selected = text.is_some_and(|text| text.contains("1 passed; 0 failed; 0 ignored"));
        let mut results = text
            .into_iter()
            .flat_map(str::lines)
            .filter_map(|line| line.strip_prefix(RUNNER_GATE_RESULT));
        let result_line = results.next();
        let result =
            result_line.and_then(|line| serde_json::from_str::<RunnerGateResult>(line).ok());
        let extra_result = results.next().is_some();
        let result_ok = !extra_result
            && match subject {
                RunnerGateSubject::PendingPath => result.as_ref().is_some_and(|value| {
                    value.reason == Some(Reason::PathConfigurationRetained)
                        && value.after_image_authority == 1
                        && value.before_tail_consumption == 0
                        && value.end_observed
                        && value.within_end
                }),
                RunnerGateSubject::ActivationInputs => result_line.is_none(),
                #[cfg(windows)]
                RunnerGateSubject::EmptyControl => result_line.is_none(),
            };
        let io_ok = stdin_ok && stdout_ok && stderr_ok;
        if !(job_ok
            && io_ok
            && status.success()
            && ack == 1
            && selected
            && result_ok
            && stderr.is_empty()
            && !stdout_overflow
            && !stderr_overflow)
        {
            let error_text = std::str::from_utf8(&stderr).ok();
            eprintln!(
                "runner diagnostic: subject={subject:?} status={:?} job={job_accounting:?} \
                 before={job_before:?} admitted={job_admitted:?} after={job_after:?} \
                 io_ok={io_ok} ack={ack} selected={selected} result={result:?} \
                 extra_result={extra_result} stdout_bytes={} stderr_bytes={} \
                 stdout_overflow={stdout_overflow} stderr_overflow={stderr_overflow} \
                 stderr_panic={} stderr_test_spawn={} complete_binding_counterexample={}",
                status.code(),
                stdout.len(),
                stderr.len(),
                error_text.is_some_and(|text| text.contains("panicked at")),
                error_text.is_some_and(|text| text.contains("Failed to spawn")),
                error_text.is_some_and(|text| text
                    .contains("changed validated completion must refuse before new input records")),
            );
        }
        assert!(io_ok, "runner pipe I/O failed");
        assert!(job_ok, "runner Job accounting or drain failed");
        assert!(
            !stdout_overflow && !stderr_overflow,
            "runner output exceeded cap"
        );
        assert!(status.success(), "pending PATH runner assertions failed");
        assert!(
            stderr.is_empty(),
            "pending PATH runner emitted unexpected diagnostics"
        );
        assert_eq!(ack, 1);
        assert!(selected, "runner helper was not selected");
        assert!(
            result_ok,
            "runner admission result was missing or unexpected"
        );
        assert!(monotonic_ms().unwrap() < tick);
    });
}

#[test]
fn pending_path_real_runner_image_refuses_before_tail_consumption() {
    for keep in [true, false] {
        let original_image = std::env::current_exe().unwrap();
        let mut image = Vec::new();
        let image_limit = 512 * 1024 * 1024;
        File::open(&original_image)
            .unwrap()
            .take(image_limit + 1)
            .read_to_end(&mut image)
            .unwrap();
        assert!(!image.is_empty() && image.len() as u64 <= image_limit);
        let image_sha = format!("{:x}", Sha256::digest(&image));
        // Supporting images keep the old synthetic fixture semantics. The app
        // and original prepare's copied runner are actual executable libtest
        // bytes, with their real size/hash in the generated package manifest.
        let fixture = PackageFixture::with_application(cfg!(windows), image);
        let (install, mut journal) = fixture.journal(keep);
        let plan = journal.state.after_exit.as_ref().unwrap();
        assert_eq!(plan.runner.digest, image_sha);
        let runner = journal.root.join(&plan.runner.relative);
        let seal = read_seal(&journal, deadline()).unwrap();
        assert!(verify(&journal.root, &plan.runner, &seal.policy, deadline(), false).unwrap());
        drop(install);

        // A synthetic historical acknowledgement tests ordering only. It does
        // not claim actual native completion: the real runner remains present.
        if cfg!(windows) {
            let sequence = journal.state.sequence + 1;
            let plan = journal.state.after_exit.as_mut().unwrap();
            plan.deadline_tick = Some(1);
            plan.payload_complete = true;
            plan.tail_pending = true;
            plan.tail_handoff_sequence = Some(sequence);
            journal.save(deadline()).unwrap();
            let plan = journal.state.after_exit.as_ref().unwrap();
            let receipt = fs::read(journal.receipt_path()).unwrap();
            let result = json!({
                "schema": "asg.uninstall-tail-result/v1",
                "nonce": journal.state.owner.nonce,
                "seal_sha256": plan.seal.digest,
                "receipt_sequence": sequence,
                "receipt_sha256": format!("{:x}", Sha256::digest(&receipt)),
                "deadline_tick": 1,
                "tail_removed": true, "runner_removed": true,
                "complete": true, "reason": "complete",
            });
            private_file(
                &journal
                    .root
                    .join(format!("helper/tail-result-{sequence:06}.json")),
                &serde_json::to_vec(&result).unwrap(),
            );
            assert_eq!(
                validated_tail_result(&journal, &seal, sequence, deadline()).unwrap(),
                Some(TailReceiptCompletion::Complete)
            );
        }
        for complete_path_with_retained_reason in [false, true] {
            journal.state.report.path = Some(if complete_path_with_retained_reason {
                json!({"status":"complete","registration_present":false,"installation_bound":true})
            } else {
                json!({"status":"incomplete","reason":"recovery_required","installation_bound":true})
            });
            journal
                .state
                .report
                .pending(Reason::PathConfigurationRetained);
            journal.save(deadline()).unwrap();
            let sequence = journal.state.sequence;
            let before = runner_gate_inventory(&fixture);
            // Preparation and snapshots precede this single original request
            // end. No schedule(), renewed recovery end or nested child is used.
            let end = deadline();
            let request = RunnerGateRequest {
                prefix: fixture.prefix.clone(),
                catalog: fixture.catalog.clone(),
                nonce: journal.state.owner.nonce.clone(),
                tick: deadline_tick(end).unwrap(),
            };
            call_pending_path_runner(&runner, &request, end);
            assert!(
                runner_gate_inventory(&fixture) == before,
                "pending PATH runner changed input bytes or native identities"
            );
            let reopened = open_journal(&fixture.prefix, &fixture.catalog, deadline()).unwrap();
            assert_eq!(reopened.state.sequence, sequence);
            assert!(
                reopened
                    .state
                    .report
                    .reasons
                    .contains(&Reason::PathConfigurationRetained)
            );
            assert_eq!(
                serde_json::to_vec(&reopened.state).unwrap(),
                serde_json::to_vec(&journal.state).unwrap()
            );
        }
    }
}

/// Produce completed synthetic receipts without executing a helper or service.
fn completed_package_fixture(keep: bool) -> (PackageFixture, Journal) {
    let (fixture, journal) = package_fixture_for_finalize(keep);
    complete_prepared_package_fixture(fixture, journal)
}

fn complete_prepared_package_fixture(
    fixture: PackageFixture,
    mut journal: Journal,
) -> (PackageFixture, Journal) {
    let seal = read_seal(&journal, deadline()).unwrap();
    for proof in &seal.metadata.removable {
        if verify(&fixture.root, proof, &seal.policy, deadline(), true).unwrap() {
            remove_exact(&fixture.root, proof, &seal.policy, deadline()).unwrap();
        }
    }
    for proof in &seal.package_files {
        remove_exact(&fixture.prefix, proof, &seal.policy, deadline()).unwrap();
    }
    remove_exact(&journal.root, &seal.runner, &seal.policy, deadline()).unwrap();
    if let Some(tail) = &seal.tail {
        remove_exact(&journal.root, tail, &seal.policy, deadline()).unwrap();
    }
    journal.state.report.package_cleanup_pending = false;
    journal.state.report.private_metadata_cleanup_pending = false;
    journal.state.report.after_exit_cleanup_pending = cfg!(windows);
    journal.state.report.reasons.clear();
    let next_sequence = journal.state.sequence + 1;
    let plan = journal.state.after_exit.as_mut().unwrap();
    plan.payload_complete = true;
    plan.tail_pending = cfg!(windows);
    if cfg!(windows) {
        // Historical acknowledgement may be older than the current call. Its
        // tick is compared byte-for-byte and never converted into new time.
        plan.deadline_tick = Some(1);
        plan.tail_handoff_sequence = Some(next_sequence);
        journal
            .state
            .report
            .reasons
            .push(Reason::AfterExitCleanupPending);
    } else {
        journal.state.report.cleanup_pending = false;
        journal.state.report.status = "complete_with_retained_private_markers".into();
    }
    journal.save(deadline()).unwrap();
    if cfg!(windows) {
        let plan = journal.state.after_exit.as_ref().unwrap();
        let receipt = fs::read(journal.receipt_path()).unwrap();
        let result = json!({
            "schema": "asg.uninstall-tail-result/v1",
            "nonce": journal.state.owner.nonce,
            "seal_sha256": plan.seal.digest,
            "receipt_sequence": journal.state.sequence,
            "receipt_sha256": format!("{:x}", Sha256::digest(&receipt)),
            "deadline_tick": 1,
            "tail_removed": true,
            "runner_removed": true,
            "complete": true,
            "reason": "complete",
        });
        private_file(
            &journal.root.join(format!(
                "helper/tail-result-{:06}.json",
                journal.state.sequence
            )),
            &serde_json::to_vec(&result).unwrap(),
        );
    }
    (fixture, journal)
}

fn with_completion_inputs<T>(
    fixture: &PackageFixture,
    journal: &mut Journal,
    operation: impl FnOnce(&mut Journal, &mut CompletionGuards<'_>, &CompletionMode<'_, '_>) -> T,
) -> T {
    let end = deadline();
    let seal = read_seal(journal, end).unwrap();
    let parent_exit =
        exit_lock(&journal.root, &seal.parent_exit, &seal.policy, end, false).unwrap();
    let runner_exit =
        exit_lock(&journal.root, &seal.runner_exit, &seal.policy, end, false).unwrap();
    let prefix = update_state::acquire_installation_lock(&fixture.prefix, end).unwrap();
    let authority = fixture.control.as_ref().map(|control| {
        control
            .with_runtime_deadline(end, || control.bind_installation(&fixture.prefix, &prefix))
            .unwrap()
    });
    let mut cleanup = drain_owners(journal, end).unwrap();
    let history = acquire(
        &fixture.root,
        LockKind::HistoryReaders,
        end,
        Reason::PrivateMetadataCleanupPending,
    )
    .unwrap();
    let (drains, writer) = cleanup.split_for_completion();
    let installation = id(&seal.owner.installation_id);
    let incarnation = id(&seal.catalog_incarnation);
    let owner = id(&seal.owner.nonce);
    let retired = if journal.state.owner.keep_data {
        None
    } else {
        Some(
            ControlRetirement::try_resume_with_deadline(
                &fixture.root,
                &fixture.prefix,
                &prefix,
                RetirementBinding {
                    installation: &installation,
                    catalog_incarnation: &incarnation,
                    operation: &owner,
                },
                drains,
                end,
            )
            .unwrap(),
        )
    };
    let mode = match (&fixture.control, &authority, &retired) {
        (Some(control), Some(installation), None) => CompletionMode::KeepData {
            control,
            installation,
        },
        (None, None, Some(retirement)) => CompletionMode::Default { retirement },
        _ => panic!("incoherent synthetic completion mode"),
    };
    let mut guards = CompletionGuards {
        parent_exit: &parent_exit,
        runner_exit: &runner_exit,
        prefix: &prefix,
        drains,
        writer,
        history: &history,
    };
    operation(journal, &mut guards, &mode)
}

/// Instrument only this test's thread and original control connection. SQLite's
/// extension registry is process-wide, but neither callback borrows this state.
mod inspector_sql_denial {
    use super::{Instant, SqliteControlStore, time};
    use rusqlite::ffi;
    use std::{
        cell::Cell,
        ffi::{CStr, c_char, c_int, c_void},
        marker::PhantomData,
        ptr::{self, NonNull},
        rc::Rc,
        sync::{Mutex, MutexGuard},
    };

    static REGISTRATION: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, Default)]
    pub(super) struct Counts {
        connections: u64,
        callbacks: u64,
        refusals: u64,
        foreign_callbacks: u64,
        reads: [u64; 3],
    }

    #[derive(Clone, Copy)]
    struct Watch {
        enabled: bool,
        capture: bool,
        active: bool,
        target: *mut ffi::sqlite3,
        ambiguous: bool,
        failed: bool,
        counts: Counts,
    }

    thread_local! {
        static WATCH: Cell<Watch> = const { Cell::new(Watch {
            enabled: false,
            capture: false,
            active: false,
            target: ptr::null_mut(),
            ambiguous: false,
            failed: false,
            counts: Counts {
                connections: 0,
                callbacks: 0,
                refusals: 0,
                foreign_callbacks: 0,
                reads: [0; 3],
            },
        }) };
    }

    unsafe fn argument_is(argument: *const c_char, expected: &[u8]) -> bool {
        // SAFETY: SQLite supplies either NULL or a callback-lived C string.
        !argument.is_null()
            && unsafe { CStr::from_ptr(argument) }
                .to_bytes()
                .eq_ignore_ascii_case(expected)
    }

    unsafe extern "C" fn authorize(
        userdata: *mut c_void,
        action: c_int,
        first: *const c_char,
        second: *const c_char,
        database: *const c_char,
        _trigger: *const c_char,
    ) -> c_int {
        WATCH
            .try_with(|slot| {
                let mut watch = slot.get();
                if !watch.enabled {
                    return ffi::SQLITE_OK;
                }
                let db = userdata.cast::<ffi::sqlite3>();
                watch.counts.callbacks = watch.counts.callbacks.saturating_add(1);
                if watch.capture {
                    if watch.target.is_null() {
                        watch.target = db;
                    } else if watch.target != db {
                        watch.ambiguous = true;
                    }
                }
                if !watch.active {
                    watch.failed |= db.is_null();
                    slot.set(watch);
                    return ffi::SQLITE_OK;
                }
                if db.is_null() || db != watch.target {
                    watch.counts.foreign_callbacks =
                        watch.counts.foreign_callbacks.saturating_add(1);
                    watch.counts.refusals = watch.counts.refusals.saturating_add(1);
                    slot.set(watch);
                    return ffi::SQLITE_DENY;
                }
                // SAFETY: these arguments live for this SQLite callback only.
                let allowed = unsafe {
                    match action {
                        ffi::SQLITE_READ | ffi::SQLITE_SELECT | ffi::SQLITE_RECURSIVE => true,
                        ffi::SQLITE_TRANSACTION => {
                            argument_is(first, b"BEGIN")
                                || argument_is(first, b"COMMIT")
                                || argument_is(first, b"ROLLBACK")
                        }
                        ffi::SQLITE_SAVEPOINT => {
                            argument_is(first, b"BEGIN")
                                || argument_is(first, b"RELEASE")
                                || argument_is(first, b"ROLLBACK")
                        }
                        ffi::SQLITE_FUNCTION => {
                            argument_is(second, b"count") || argument_is(second, b"like")
                        }
                        ffi::SQLITE_PRAGMA => {
                            second.is_null()
                                && (argument_is(first, b"user_version")
                                    || argument_is(first, b"application_id"))
                        }
                        _ => false,
                    }
                };
                if allowed && action == ffi::SQLITE_READ {
                    // SAFETY: use the names only while SQLite lends them.
                    if unsafe { argument_is(database, b"main") } {
                        for (index, table) in [
                            b"control_meta".as_slice(),
                            b"purge_jobs".as_slice(),
                            b"backup_manifests".as_slice(),
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            if unsafe { argument_is(first, table) } {
                                watch.counts.reads[index] =
                                    watch.counts.reads[index].saturating_add(1);
                            }
                        }
                    }
                }
                if !allowed {
                    watch.counts.refusals = watch.counts.refusals.saturating_add(1);
                }
                slot.set(watch);
                if allowed {
                    ffi::SQLITE_OK
                } else {
                    ffi::SQLITE_DENY
                }
            })
            .unwrap_or(ffi::SQLITE_DENY)
    }

    unsafe extern "C" fn connection_created(
        db: *mut ffi::sqlite3,
        _error: *mut *mut c_char,
        _api: *const ffi::sqlite3_api_routines,
    ) -> c_int {
        let install = WATCH
            .try_with(|slot| {
                let mut watch = slot.get();
                if !watch.enabled {
                    return None;
                }
                // Count at entry, even if open/installation is subsequently refused.
                watch.counts.connections = watch.counts.connections.saturating_add(1);
                let refuse = watch.capture || watch.active || db.is_null();
                watch.failed |= refuse;
                slot.set(watch);
                Some(!refuse)
            })
            .unwrap_or(None);
        match install {
            None => ffi::SQLITE_OK,
            Some(false) => ffi::SQLITE_AUTH,
            Some(true) => {
                // SAFETY: SQLite lends a live new connection. The userdata is
                // that connection, not registration memory; no ownership passes.
                let rc = unsafe {
                    ffi::sqlite3_set_authorizer(db, Some(authorize), db.cast::<c_void>())
                };
                if rc != ffi::SQLITE_OK {
                    let _ = WATCH.try_with(|slot| {
                        let mut watch = slot.get();
                        watch.failed = true;
                        slot.set(watch);
                    });
                }
                rc
            }
        }
    }

    pub(super) struct InspectorExtension {
        _registration: MutexGuard<'static, ()>,
        _thread: PhantomData<Rc<()>>,
        registered: bool,
    }

    impl InspectorExtension {
        pub(super) fn register() -> Self {
            assert!(!WATCH.with(|slot| slot.get().enabled));
            let mut extension = Self {
                _registration: REGISTRATION
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()),
                _thread: PhantomData,
                registered: false,
            };
            // SAFETY: both callbacks are static, nonpanicking and never open or
            // close a database or alter the extension registry from a callback.
            let rc = unsafe { ffi::sqlite3_auto_extension(Some(connection_created)) };
            assert_eq!(rc, ffi::SQLITE_OK);
            extension.registered = true;
            WATCH.with(|slot| {
                let mut watch = slot.get();
                watch.enabled = true;
                watch.failed = false;
                watch.ambiguous = false;
                watch.counts = Counts::default();
                slot.set(watch);
            });
            extension
        }

        pub(super) fn arm<'registration, 'control>(
            &'registration self,
            control: &'control SqliteControlStore,
            end: Instant,
        ) -> InspectorSqlDenial<'registration, 'control> {
            time(end).unwrap();
            let before_capture = WATCH.with(|slot| {
                let mut watch = slot.get();
                assert!(watch.enabled && !watch.capture && !watch.active && !watch.failed);
                watch.capture = true;
                watch.target = ptr::null_mut();
                watch.ambiguous = false;
                slot.set(watch);
                watch.counts
            });
            let snapshot = control.lifecycle_cleanup_snapshot_with_deadline(end);
            let captured = WATCH.with(|slot| {
                let mut watch = slot.get();
                watch.capture = false;
                slot.set(watch);
                watch
            });
            // No saved-pointer FFI is permitted before ALL of these checks.
            let snapshot = snapshot.expect("the actual control snapshot must succeed");
            assert!(snapshot.purge_complete() && snapshot.backups_complete());
            assert!(!captured.failed && !captured.ambiguous);
            assert!(captured.counts.callbacks > before_capture.callbacks);
            assert_eq!(captured.counts.connections, before_capture.connections);
            let db = NonNull::new(captured.target).expect("capture must identify one connection");
            let denial = InspectorSqlDenial {
                _extension: self,
                control,
                db,
                end,
                installed: true,
            };
            // The completed snapshot has dropped every transaction/cursor. Do
            // not rely on set_authorizer's advisory statement expiration alone.
            denial.assert_no_statements();
            control
                .with_runtime_deadline(end, || {
                    for sql in [
                        c"CREATE TEMP TABLE inspector_sql_probe(value INTEGER NOT NULL)",
                        c"INSERT INTO temp.inspector_sql_probe VALUES(1)",
                    ] {
                        let (rc, statement) = denial.prepare(sql);
                        assert_eq!(rc, ffi::SQLITE_OK);
                        assert_eq!(statement.step(), ffi::SQLITE_DONE);
                        assert_eq!(statement.finish(), ffi::SQLITE_OK);
                    }
                    Ok(())
                })
                .unwrap();
            denial.assert_no_statements();
            WATCH.with(|slot| {
                let mut watch = slot.get();
                assert!(!watch.failed);
                assert_eq!(watch.counts.connections, captured.counts.connections);
                watch.active = true;
                slot.set(watch);
            });
            // SAFETY: the successful capture identified this store's original
            // connection; the guard borrows the store and registration on this
            // thread. No statement, transaction or RefCell borrow remains.
            let rc = unsafe {
                ffi::sqlite3_set_authorizer(db.as_ptr(), Some(authorize), db.as_ptr().cast())
            };
            assert_eq!(rc, ffi::SQLITE_OK);
            denial
        }

        fn cancel(&mut self) -> bool {
            let _ = WATCH.try_with(|slot| {
                let mut watch = slot.get();
                watch.enabled = false;
                watch.capture = false;
                watch.active = false;
                watch.target = ptr::null_mut();
                slot.set(watch);
            });
            if !self.registered {
                return true;
            }
            // SAFETY: remove only our static entry. SQLite returns 1 for
            // removal, not SQLITE_OK; this neither drains callbacks nor removes
            // authorizers on existing connections. They use no borrowed state.
            let removed = unsafe { ffi::sqlite3_cancel_auto_extension(Some(connection_created)) };
            self.registered = false;
            removed == 1
        }

        pub(super) fn finish(mut self) {
            assert!(
                self.cancel(),
                "the private extension must still be registered"
            );
        }
    }

    impl Drop for InspectorExtension {
        fn drop(&mut self) {
            let _ = self.cancel();
        }
    }

    pub(super) struct InspectorSqlDenial<'registration, 'control> {
        _extension: &'registration InspectorExtension,
        control: &'control SqliteControlStore,
        db: NonNull<ffi::sqlite3>,
        end: Instant,
        installed: bool,
    }

    struct Statement<'connection> {
        raw: *mut ffi::sqlite3_stmt,
        _connection: PhantomData<&'connection SqliteControlStore>,
    }

    impl Statement<'_> {
        fn step(&self) -> c_int {
            // SAFETY: only successful fixture preparation calls step, while
            // the connection is borrowed on this thread and the statement lives.
            unsafe { ffi::sqlite3_step(self.raw) }
        }

        fn finish(mut self) -> c_int {
            let raw = std::mem::replace(&mut self.raw, ptr::null_mut());
            // SAFETY: we own only this statement, never its database connection.
            unsafe { ffi::sqlite3_finalize(raw) }
        }
    }

    impl Drop for Statement<'_> {
        fn drop(&mut self) {
            // SAFETY: even unexpected prepare success/panic finalizes the
            // statement. SQLite explicitly permits finalize(NULL).
            unsafe { ffi::sqlite3_finalize(self.raw) };
        }
    }

    impl InspectorSqlDenial<'_, '_> {
        fn prepare(&self, sql: &CStr) -> (c_int, Statement<'_>) {
            time(self.end).unwrap();
            // Own the out-pointer BEFORE prepare or any assertion, including
            // when a supposedly forbidden statement unexpectedly succeeds.
            let mut statement = Statement {
                raw: ptr::null_mut(),
                _connection: PhantomData,
            };
            // SAFETY: capture proved this live borrowed connection; SQL is a
            // test-owned C string and the out-pointer belongs to the RAII guard.
            let rc = unsafe {
                ffi::sqlite3_prepare_v2(
                    self.db.as_ptr(),
                    sql.as_ptr(),
                    -1,
                    &mut statement.raw,
                    ptr::null_mut(),
                )
            };
            (rc, statement)
        }

        fn assert_no_statements(&self) {
            // SAFETY: capture succeeded and the store is still borrowed. This
            // observes the list only; it never finalizes another owner's cursor.
            assert!(unsafe { ffi::sqlite3_next_stmt(self.db.as_ptr(), ptr::null_mut()) }.is_null());
            assert_eq!(unsafe { ffi::sqlite3_get_autocommit(self.db.as_ptr()) }, 1);
        }

        pub(super) fn counts(&self) -> Counts {
            WATCH.with(|slot| {
                let watch = slot.get();
                assert!(watch.active && !watch.failed && !watch.ambiguous);
                assert!(watch.target == self.db.as_ptr());
                watch.counts
            })
        }

        pub(super) fn assert_reads_since(&self, before: Counts, phase: &str) {
            let after = self.counts();
            assert!(after.callbacks > before.callbacks, "{phase}: no actual SQL");
            assert_eq!(after.connections, before.connections, "{phase}: reopened");
            assert_eq!(after.foreign_callbacks, before.foreign_callbacks, "{phase}");
            assert_eq!(
                after.refusals, before.refusals,
                "{phase}: attempted mutation"
            );
            for (after, before) in after.reads.into_iter().zip(before.reads) {
                assert!(after > before, "{phase}: missing control/job/backup read");
            }
        }

        pub(super) fn assert_denied(&self, sql: &CStr) {
            let before = self.counts();
            self.control
                .with_runtime_deadline(self.end, || {
                    let (rc, statement) = self.prepare(sql);
                    assert_eq!(rc, ffi::SQLITE_AUTH, "mutation control must be denied");
                    // Never step a mutation control, even if prepare succeeds.
                    assert_eq!(statement.finish(), ffi::SQLITE_OK);
                    Ok(())
                })
                .unwrap();
            let after = self.counts();
            assert!(after.refusals > before.refusals);
            assert_eq!(after.connections, before.connections);
            assert_eq!(after.foreign_callbacks, before.foreign_callbacks);
        }

        fn uninstall(&mut self) -> c_int {
            if !self.installed {
                return ffi::SQLITE_OK;
            }
            // SAFETY: remove the authorizer before the store/registration
            // borrows end. Do not alter the store's busy/progress handlers.
            let rc =
                unsafe { ffi::sqlite3_set_authorizer(self.db.as_ptr(), None, ptr::null_mut()) };
            if rc == ffi::SQLITE_OK {
                self.installed = false;
            }
            let _ = WATCH.try_with(|slot| {
                let mut watch = slot.get();
                watch.active = false;
                watch.target = ptr::null_mut();
                slot.set(watch);
            });
            rc
        }

        pub(super) fn finish(mut self) {
            assert_eq!(self.uninstall(), ffi::SQLITE_OK);
        }
    }

    impl Drop for InspectorSqlDenial<'_, '_> {
        fn drop(&mut self) {
            let _ = self.uninstall();
        }
    }
}

#[test]
fn completed_inspection_uses_the_original_connection_with_sql_mutations_denied() {
    let extension = inspector_sql_denial::InspectorExtension::register();
    // Register before any fixture connection exists; preparation remains writable.
    let (fixture, mut journal) = completed_package_fixture(true);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let CompletionMode::KeepData { control, .. } = mode else {
            panic!("this test needs the actual retained control connection");
        };
        let before = borrowed_keep_data_inventory(&fixture);
        let state = serde_json::to_vec(&journal.state).unwrap();
        let end = deadline();
        let denial = extension.arm(control, end);
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);

        // This other thread encounters the registered extension while denial is
        // active here, but receives no authorizer and can mutate its own database.
        std::thread::spawn(|| {
            let connection = rusqlite::Connection::open_in_memory().unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE unrelated(value);
                     CREATE TEMP TABLE unrelated_temp(value);
                     INSERT INTO unrelated VALUES(1);
                     INSERT INTO unrelated_temp VALUES(1);
                     UPDATE unrelated SET value=2;
                     UPDATE unrelated_temp SET value=2;
                     DELETE FROM unrelated;
                     DELETE FROM unrelated_temp;",
                )
                .unwrap();
        })
        .join()
        .unwrap();

        // Capture/preparation observations cannot satisfy any of these deltas.
        let inspection = denial.counts();
        let mut completed = inspect_completed_uninstall(journal, guards, mode, end).unwrap();
        denial.assert_reads_since(inspection, "inspection");
        let revalidation = denial.counts();
        completed.validate_current().unwrap();
        denial.assert_reads_since(revalidation, "revalidation");
        for sql in [
            c"CREATE TABLE inspector_forbidden(value)",
            c"CREATE TEMP TABLE inspector_forbidden(value)",
            c"INSERT INTO main.control_meta SELECT * FROM main.control_meta",
            c"UPDATE main.control_meta SET control_seq=control_seq",
            c"DELETE FROM main.control_meta",
            c"INSERT INTO temp.inspector_sql_probe VALUES(2)",
            c"UPDATE temp.inspector_sql_probe SET value=2",
            c"DELETE FROM temp.inspector_sql_probe",
            c"PRAGMA user_version=1",
            c"PRAGMA wal_checkpoint",
        ] {
            denial.assert_denied(sql);
        }
        let after_controls = denial.counts();
        completed.validate_current().unwrap();
        denial.assert_reads_since(after_controls, "revalidation after denial controls");
        drop(completed);
        assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state);
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        denial.finish();
    });
    drop(fixture);
    extension.finish();
}

#[test]
fn completed_inspection_preserves_both_modes_and_excludes_live_contenders() {
    use crate::uninstall_command::tests::{ControlValidationRead, with_control_validation_hook};
    use std::cell::Cell;

    for keep in [true, false] {
        let (fixture, mut journal) = completed_package_fixture(keep);
        let source = fixture._temp.path().join("untouched-source.jsonl");
        private_file(&source, b"synthetic source retained");
        with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
            let before = borrowed_keep_data_inventory(&fixture);
            let state = serde_json::to_vec(&journal.state).unwrap();
            let writer = guards.writer.read_record().unwrap();
            let opens = Rc::new(Cell::new(0));
            let observed = Rc::clone(&opens);
            with_control_validation_hook(
                move |step| {
                    if step == ControlValidationRead::Open {
                        observed.set(observed.get() + 1);
                        Err(PortError::Backend("synthetic reopen refused".into()))
                    } else {
                        Ok(())
                    }
                },
                || {
                    if let CompletionMode::KeepData { control, .. } = mode {
                        assert!(matches!(
                            journal.validate(control, deadline()),
                            Err(Reason::IdentityChanged)
                        ));
                        assert_eq!(opens.get(), 1);
                    }
                    for _ in 0..2 {
                        let mut completed =
                            inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
                        completed.validate_current().unwrap();
                        for kind in [
                            LockKind::PolicyEmission,
                            LockKind::Supervisor,
                            LockKind::Background,
                            managed_purge::purge_lock_kind().unwrap(),
                            LockKind::CatalogHandles,
                            LockKind::PolicyOwner,
                            LockKind::HistoryReaders,
                        ] {
                            assert!(matches!(
                                ExclusiveGuard::try_acquire(&fixture.root, kind),
                                Err(PortError::WriterBusy(_))
                            ));
                        }
                        assert!(matches!(
                            ExclusiveGuard::try_acquire(
                                &fixture.prefix,
                                LockKind::MaintenanceJob(
                                    JobLockKey::parse(INSTALLATION_LOCK_KEY).unwrap()
                                )
                            ),
                            Err(PortError::WriterBusy(_))
                        ));
                        let seal = read_seal(journal, deadline()).unwrap();
                        for proof in [&seal.parent_exit, &seal.runner_exit] {
                            assert!(matches!(
                                exit_lock(&journal.root, proof, &seal.policy, deadline(), false),
                                Err(Reason::AfterExitCleanupPending)
                            ));
                        }
                        assert!(matches!(
                            WriterLease::try_acquire(&fixture.root),
                            Err(PortError::WriterBusy(_))
                        ));
                        if !keep {
                            assert!(matches!(
                                ExclusiveGuard::try_acquire(
                                    &fixture.root,
                                    LockKind::ControlHandles
                                ),
                                Err(PortError::WriterBusy(_))
                            ));
                        }
                    }
                    assert_eq!(opens.get(), u32::from(keep));
                },
            );
            assert_eq!(guards.writer.read_record().unwrap(), writer);
            assert_eq!(borrowed_keep_data_inventory(&fixture), before);
            assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state);
        });
        let contender = ExclusiveGuard::try_acquire(&fixture.root, LockKind::PolicyOwner).unwrap();
        drop(contender);
        assert_eq!(fs::read(source).unwrap(), b"synthetic source retained");
    }
}

#[test]
fn completed_inspection_refuses_real_pending_purge_with_coherent_receipt() {
    use agent_session_grep_ports::{
        SearchProvider,
        control::{ScopeRegion, SelectionRequest},
    };

    let fixture = PackageFixture::new(cfg!(windows));
    let control = fixture.control.as_ref().unwrap();
    let revoked = control
        .with_runtime_deadline(deadline(), || {
            let status = control.lifecycle_status()?;
            let selected = control.add_selection(
                status.policy.control_seq,
                SelectionRequest {
                    region: ScopeRegion {
                        provider: SearchProvider::Claude,
                        locator: CanonicalLocator::from_path(
                            &fixture._temp.path().join("synthetic-purge-selection"),
                        )?,
                        kind: RootKind::Root,
                    },
                    root_identity: Some(id("synthetic-purge-selection-root")),
                    now_ms: 2,
                },
            )?;
            control.revoke_selection(selected.control_seq, &selected.value.id, None, 3)
        })
        .unwrap();
    assert_eq!(revoked.value.purge_job.state, PurgeState::Pending);
    let (install, journal) = fixture.journal(true);
    drop(install);
    let (fixture, mut journal) = complete_prepared_package_fixture(fixture, journal);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let CompletionMode::KeepData {
            control,
            installation,
        } = mode
        else {
            panic!("keep-data fixture must lend the original connection");
        };
        let seal = read_seal(journal, deadline()).unwrap();
        completion_history(journal, &seal, deadline()).unwrap();
        assert_eq!(
            completed_receipt(journal, &seal, deadline()).unwrap(),
            journal
                .state
                .after_exit
                .as_ref()
                .unwrap()
                .tail_handoff_sequence
        );
        validate_borrowed_keep_data_with_owner(
            journal,
            &seal,
            control,
            installation,
            guards.drains.policy_owner,
            deadline(),
        )
        .unwrap();
        let snapshot = control
            .lifecycle_cleanup_snapshot_with_deadline(deadline())
            .unwrap();
        assert!(!snapshot.purge_complete());
        assert!(snapshot.backups_complete());
        let policy = control
            .with_runtime_deadline(deadline(), || control.lifecycle_status())
            .unwrap();
        let before = borrowed_keep_data_inventory(&fixture);
        let state = serde_json::to_vec(&journal.state).unwrap();
        assert!(matches!(
            inspect_completed_uninstall(journal, guards, mode, deadline()),
            Err(Reason::PurgePrerequisitePending)
        ));
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state);
        assert_eq!(
            control
                .with_runtime_deadline(deadline(), || control.lifecycle_status())
                .unwrap(),
            policy
        );

        // Fixture-only transition of the real typed job, leaving seal/counters
        // unchanged. Only completing this row may remove the refusal.
        let conn = rusqlite::Connection::open_with_flags(
            SqliteControlStore::path(&fixture.root),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(
            conn.execute(
                "UPDATE purge_jobs SET state='complete',attempts=1,
                 progress_key='asg.purge/v1:artifacts_verified',owner_nonce=NULL
                 WHERE job_id=?1 AND state='pending'",
                [revoked.value.purge_job.id.as_str()],
            )
            .unwrap(),
            1
        );
        drop(conn);
        let mut completed = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
        completed.validate_current().unwrap();
    });
}

#[test]
fn completed_inspection_refuses_real_nonterminal_backup_with_coherent_receipt() {
    let (fixture, mut journal) = completed_package_fixture(true);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let CompletionMode::KeepData {
            control,
            installation,
        } = mode
        else {
            panic!("keep-data fixture must lend the original connection");
        };
        let policy = control
            .with_runtime_deadline(deadline(), || control.lifecycle_status())
            .unwrap();
        let seal = read_seal(journal, deadline()).unwrap();
        // Fixture-only insertion keeps every policy/receipt field unchanged and
        // uses the adapter's coherent Registered artifact/backup row pair.
        let mut conn = rusqlite::Connection::open_with_flags(
            SqliteControlStore::path(&fixture.root),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(
            "INSERT INTO private_artifacts
             (artifact_id,kind,relative_locator,policy_epoch,owner_nonce,state,digest)
             VALUES('synthetic-pending-backup','catalog_backup',
             'backups/synthetic-pending-backup/catalog.db',?1,?2,'registered',NULL)",
            rusqlite::params![seal.policy.policy_epoch, journal.state.owner.nonce],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO backup_manifests
             (backup_id,purpose,relative_locator,catalog_incarnation,catalog_generation,
              schema_version,digest,size_bytes,state,created_at_ms)
             VALUES('synthetic-pending-backup','beta_rollback',
             'backups/synthetic-pending-backup/catalog.db',?1,0,?2,'',0,'registered',1)",
            rusqlite::params![journal.state.catalog_incarnation, SCHEMA_VERSION],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            control
                .with_runtime_deadline(deadline(), || control.lifecycle_status())
                .unwrap(),
            policy
        );
        completion_history(journal, &seal, deadline()).unwrap();
        assert_eq!(
            completed_receipt(journal, &seal, deadline()).unwrap(),
            journal
                .state
                .after_exit
                .as_ref()
                .unwrap()
                .tail_handoff_sequence
        );
        validate_borrowed_keep_data_with_owner(
            journal,
            &seal,
            control,
            installation,
            guards.drains.policy_owner,
            deadline(),
        )
        .unwrap();
        let snapshot = control
            .lifecycle_cleanup_snapshot_with_deadline(deadline())
            .unwrap();
        assert!(snapshot.purge_complete());
        assert!(!snapshot.backups_complete());
        let before = borrowed_keep_data_inventory(&fixture);
        let state = serde_json::to_vec(&journal.state).unwrap();
        assert!(matches!(
            inspect_completed_uninstall(journal, guards, mode, deadline()),
            Err(Reason::BackupCleanupPending)
        ));
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state);
        assert_eq!(
            conn.query_row(
                "SELECT state FROM backup_manifests WHERE backup_id='synthetic-pending-backup'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "registered"
        );
        // A typed policy-purged tombstone is permitted; it grants no backup
        // content or restoration authority and preserves the same sealed policy.
        conn.execute_batch(
            "BEGIN;
             UPDATE private_artifacts SET state='purged_by_policy',owner_nonce=NULL
             WHERE artifact_id='synthetic-pending-backup';
             UPDATE backup_manifests SET state='purged_by_policy'
             WHERE backup_id='synthetic-pending-backup';
             COMMIT;",
        )
        .unwrap();
        drop(conn);
        let mut completed = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
        completed.validate_current().unwrap();
    });
}

#[test]
fn completed_inspection_refuses_wrong_modes_foreign_retirement_and_live_fence_changes() {
    let (kept, mut kept_journal) = completed_package_fixture(true);
    let (removed, mut removed_journal) = completed_package_fixture(false);
    let (foreign, mut foreign_journal) = completed_package_fixture(false);
    with_completion_inputs(
        &kept,
        &mut kept_journal,
        |kept_journal, kept_guards, kept_mode| {
            with_completion_inputs(
                &removed,
                &mut removed_journal,
                |removed_journal, removed_guards, removed_mode| {
                    let before_kept = borrowed_keep_data_inventory(&kept);
                    let before_removed = borrowed_keep_data_inventory(&removed);
                    assert!(matches!(
                        inspect_completed_uninstall(
                            kept_journal,
                            kept_guards,
                            removed_mode,
                            deadline()
                        ),
                        Err(Reason::IdentityChanged)
                    ));
                    assert!(matches!(
                        inspect_completed_uninstall(
                            removed_journal,
                            removed_guards,
                            kept_mode,
                            deadline()
                        ),
                        Err(Reason::IdentityChanged)
                    ));
                    with_completion_inputs(&foreign, &mut foreign_journal, |_, _, foreign_mode| {
                        let before_foreign = borrowed_keep_data_inventory(&foreign);
                        assert!(matches!(
                            inspect_completed_uninstall(
                                removed_journal,
                                removed_guards,
                                foreign_mode,
                                deadline()
                            ),
                            Err(Reason::IdentityChanged)
                        ));
                        assert_eq!(borrowed_keep_data_inventory(&foreign), before_foreign);
                    });
                    assert_eq!(borrowed_keep_data_inventory(&kept), before_kept);
                    assert_eq!(borrowed_keep_data_inventory(&removed), before_removed);
                },
            );
            let CompletionMode::KeepData {
                control,
                installation,
            } = kept_mode
            else {
                panic!("keep-data fixture must lend the original connection");
            };
            let bound = control
                .bind_control_root(kept_guards.drains.policy_owner)
                .unwrap();
            let owner = id(&kept_journal.state.owner.nonce);
            let status = control
                .with_runtime_deadline(deadline(), || {
                    let status = control.lifecycle_status()?;
                    control.begin_maintenance(
                        status.policy.control_seq,
                        &owner,
                        &bound,
                        installation,
                        MaintenanceFence {
                            state: MaintenanceState::Updating,
                            owner: Some(owner.clone()),
                            phase: Some(MaintenancePhase::Quiescing),
                        },
                    )?;
                    control.lifecycle_status()
                })
                .unwrap();
            let before = borrowed_keep_data_inventory(&kept);
            assert!(matches!(
                inspect_completed_uninstall(kept_journal, kept_guards, kept_mode, deadline()),
                Err(Reason::MaintenanceConflict)
            ));
            assert_eq!(borrowed_keep_data_inventory(&kept), before);
            assert_eq!(
                control
                    .with_runtime_deadline(deadline(), || control.lifecycle_status())
                    .unwrap(),
                status
            );
        },
    );
}

#[test]
fn completed_inspection_refuses_missing_linked_and_same_byte_replaced_catalog() {
    let (fixture, mut journal) = completed_package_fixture(true);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let original = fixture._temp.path().join("saved-catalog");
        fs::rename(&fixture.catalog, &original).unwrap();
        let before = borrowed_keep_data_inventory(&fixture);
        assert!(matches!(
            inspect_completed_uninstall(journal, guards, mode, deadline()),
            Err(Reason::CorpusCleanupPending)
        ));
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        private_file(&fixture.catalog, &fs::read(&original).unwrap());
        let before = borrowed_keep_data_inventory(&fixture);
        assert!(matches!(
            inspect_completed_uninstall(journal, guards, mode, deadline()),
            Err(Reason::IdentityChanged)
        ));
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        fs::remove_file(&fixture.catalog).unwrap();
        fs::rename(&original, &fixture.catalog).unwrap();
        fs::hard_link(&fixture.catalog, &original).unwrap();
        let before = borrowed_keep_data_inventory(&fixture);
        assert!(inspect_completed_uninstall(journal, guards, mode, deadline()).is_err());
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        fs::remove_file(&original).unwrap();
        {
            let mut completed =
                inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
            completed.validate_current().unwrap();
        }
        fs::rename(&fixture.catalog, &original).unwrap();
        private_root(&fixture.catalog);
        let before = borrowed_keep_data_inventory(&fixture);
        assert!(inspect_completed_uninstall(journal, guards, mode, deadline()).is_err());
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        fs::remove_dir(&fixture.catalog).unwrap();
        fs::rename(&original, &fixture.catalog).unwrap();
        let _completed = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
    });
}

#[test]
fn completed_inspection_rejects_swapped_exit_roles_and_wrong_drain_bindings() {
    let (fixture, mut journal) = completed_package_fixture(true);
    let other = fixture
        ._temp
        .path()
        .canonicalize()
        .unwrap()
        .join("other-data");
    private_root(&other);
    let other_guard = ExclusiveGuard::try_acquire(&other, LockKind::PolicyOwner).unwrap();
    let mut other_writer = WriterLease::try_acquire(&other).unwrap();
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let before = borrowed_keep_data_inventory(&fixture);
        for case in 0..11 {
            let mut drains = guards.drains;
            match case {
                2 => drains.emission = guards.drains.background,
                3 => drains.supervisor = guards.drains.background,
                4 => drains.background = guards.drains.supervisor,
                5 => drains.purge = guards.drains.background,
                6 => drains.catalog_handles = guards.drains.background,
                7 => drains.policy_owner = &other_guard,
                _ => {}
            }
            let mut wrong = CompletionGuards {
                parent_exit: if case == 0 {
                    guards.runner_exit
                } else {
                    guards.parent_exit
                },
                runner_exit: if case == 1 {
                    guards.parent_exit
                } else {
                    guards.runner_exit
                },
                prefix: if case == 8 {
                    &other_guard
                } else {
                    guards.prefix
                },
                drains,
                writer: if case == 9 {
                    &mut other_writer
                } else {
                    &mut *guards.writer
                },
                history: if case == 10 {
                    guards.drains.background
                } else {
                    guards.history
                },
            };
            assert!(
                inspect_completed_uninstall(journal, &mut wrong, mode, deadline()).is_err(),
                "{case}"
            );
            assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        }
        let _completed = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
    });
}

#[test]
fn completed_inspection_refuses_unfinished_receipts_and_surviving_payload() {
    for case in [
        "purge", "cache", "private", "package", "group", "runner", "unknown",
    ] {
        let (fixture, mut journal) = completed_package_fixture(true);
        with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
            let seal = read_seal(journal, deadline()).unwrap();
            match case {
                "purge" => journal.state.purge_prerequisite_complete = false,
                "cache" => journal.state.report.continuation_cache_cleared = false,
                "private" => journal.state.report.private_metadata_cleanup_pending = true,
                "package" => journal.state.after_exit.as_mut().unwrap().payload_complete = false,
                "group" => journal.state.groups.push(RemovalGroup {
                    kind: GroupKind::Backup,
                    files: Vec::new(),
                    removed: false,
                }),
                "runner" => private_file(
                    &journal.root.join(&seal.runner.relative),
                    b"replacement runner",
                ),
                "unknown" => private_file(&fixture.root.join("unknown-residue"), b"unclassified"),
                _ => unreachable!(),
            }
            if !matches!(case, "runner" | "unknown") {
                journal.save(deadline()).unwrap();
            }
            let before = borrowed_keep_data_inventory(&fixture);
            assert!(
                inspect_completed_uninstall(journal, guards, mode, deadline()).is_err(),
                "{case}"
            );
            assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        });
    }
}

#[test]
fn completed_inspection_requires_contiguous_exact_history_and_two_equal_passes() {
    let (fixture, mut journal) = completed_package_fixture(true);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let first = journal.root.join("state-000001.json");
        let missing = fixture._temp.path().join("saved-first-state");
        fs::rename(&first, &missing).unwrap();
        let before = borrowed_keep_data_inventory(&fixture);
        assert!(inspect_completed_uninstall(journal, guards, mode, deadline()).is_err());
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        fs::rename(missing, &first).unwrap();
        let bytes = fs::read(&first).unwrap();
        let path = first.clone();
        let changed = [bytes.as_slice(), b"\n"].concat();
        let expected = changed.clone();
        with_completion_pass_hook(
            move |_| fs::write(&path, &changed).unwrap(),
            || {
                assert!(matches!(
                    inspect_completed_uninstall(journal, guards, mode, deadline()),
                    Err(Reason::IdentityChanged)
                ));
            },
        );
        assert_eq!(fs::read(&first).unwrap(), expected);
        fs::write(&first, bytes).unwrap();
        let _completed = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
    });
}

#[test]
fn completed_inspection_checks_live_proof_again_and_keeps_the_original_end() {
    let (fixture, mut journal) = completed_package_fixture(true);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let before = borrowed_keep_data_inventory(&fixture);
        assert!(matches!(
            inspect_completed_uninstall(journal, guards, mode, Instant::now()),
            Err(Reason::Deadline)
        ));
        {
            let mut proof = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
            let extra = fixture.root.join("new-residue");
            private_file(&extra, b"cannot be ignored");
            assert!(matches!(
                proof.validate_current(),
                Err(Reason::UnclassifiedOwnedArtifact)
            ));
            fs::remove_file(extra).unwrap();
            proof.validate_current().unwrap();
        }
        let end = Instant::now() + Duration::from_secs(2);
        let requested = end + Duration::from_secs(10);
        let control = fixture.control.as_ref().unwrap();
        let result = control.with_runtime_deadline(end, || {
            with_completion_pass_hook(
                move |_| {
                    std::thread::sleep(
                        end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                    )
                },
                || {
                    assert!(matches!(
                        inspect_completed_uninstall(journal, guards, mode, requested),
                        Err(Reason::Deadline)
                    ));
                },
            );
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(requested),
                end
            );
            Ok(())
        });
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(requested),
            requested
        );
        assert_eq!(borrowed_keep_data_inventory(&fixture), before);
    });
}

#[test]
fn completed_inspection_never_promotes_pending_or_repairs_retirement_markers() {
    let (fixture, mut journal) = completed_package_fixture(false);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let published = fixture.root.join(RETIREMENT_MARKER);
        let pending = fixture.root.join(RETIREMENT_PENDING_MARKER);
        let original = fs::read(&published).unwrap();
        for case in ["pending", "both", "corrupt", "absent"] {
            match case {
                "pending" => fs::rename(&published, &pending).unwrap(),
                "both" => private_file(&pending, &original),
                "corrupt" => fs::write(&published, b"{}").unwrap(),
                "absent" => {
                    fs::rename(&published, fixture._temp.path().join("saved-marker")).unwrap()
                }
                _ => unreachable!(),
            }
            let before = borrowed_keep_data_inventory(&fixture);
            assert!(
                inspect_completed_uninstall(journal, guards, mode, deadline()).is_err(),
                "{case}"
            );
            assert_eq!(borrowed_keep_data_inventory(&fixture), before);
            match case {
                "pending" => fs::rename(&pending, &published).unwrap(),
                "both" => fs::remove_file(&pending).unwrap(),
                "corrupt" => fs::write(&published, &original).unwrap(),
                "absent" => {
                    fs::rename(fixture._temp.path().join("saved-marker"), &published).unwrap()
                }
                _ => unreachable!(),
            }
        }
        let _completed = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
    });
}

#[cfg(windows)]
#[test]
fn completed_inspection_binds_unconsumed_tail_to_original_receipt_and_tick() {
    let (fixture, mut journal) = completed_package_fixture(true);
    assert!(journal.state.report.after_exit_cleanup_pending);
    with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
        let sequence = journal
            .state
            .after_exit
            .as_ref()
            .unwrap()
            .tail_handoff_sequence
            .unwrap();
        let result = journal
            .root
            .join(format!("helper/tail-result-{sequence:06}.json"));
        let original = fs::read(&result).unwrap();
        for field in [
            "nonce",
            "receipt_sha256",
            "seal_sha256",
            "receipt_sequence",
            "deadline_tick",
            "complete",
        ] {
            let mut value: Value = serde_json::from_slice(&original).unwrap();
            value[field] = match field {
                "receipt_sequence" | "deadline_tick" => json!(123),
                "complete" => json!(false),
                _ => json!("synthetic-mismatch"),
            };
            fs::write(&result, serde_json::to_vec(&value).unwrap()).unwrap();
            let before = borrowed_keep_data_inventory(&fixture);
            assert!(
                inspect_completed_uninstall(journal, guards, mode, deadline()).is_err(),
                "{field}"
            );
            assert_eq!(borrowed_keep_data_inventory(&fixture), before);
        }
        fs::write(result, original).unwrap();
        let _completed = inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
        assert!(journal.state.report.after_exit_cleanup_pending);
        assert_eq!(
            journal.state.after_exit.as_ref().unwrap().deadline_tick,
            Some(1)
        );
    });
}

#[test]
fn held_installation_guard_validation_requires_kind_and_pinned_prefix() {
    let fixture = PackageFixture::new(false);
    let (_install, journal) = fixture.journal(true);
    let installation =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    validate_installation_guard(&journal, &installation, deadline()).unwrap();
    validate_installation_guard(&journal, &installation, deadline()).unwrap();
    let other_kind = ExclusiveGuard::try_acquire(&fixture.prefix, LockKind::Background).unwrap();
    assert!(matches!(
        validate_installation_guard(&journal, &other_kind, deadline()),
        Err(Reason::IdentityChanged)
    ));
    let other_root = fixture
        ._temp
        .path()
        .canonicalize()
        .unwrap()
        .join("other-prefix");
    private_root(&other_root);
    let other_installation =
        update_state::acquire_installation_lock(&other_root, deadline()).unwrap();
    assert!(matches!(
        validate_installation_guard(&journal, &other_installation, deadline()),
        Err(Reason::IdentityChanged)
    ));
    assert!(matches!(
        validate_installation_guard(&journal, &installation, Instant::now()),
        Err(Reason::Deadline)
    ));
}

#[test]
fn held_writer_proof_preserves_diagnostics_and_rejects_another_root() {
    let fixture = PackageFixture::new(false);
    let (_install, journal) = fixture.journal(true);
    let seal = read_seal(&journal, deadline()).unwrap();
    let mut writer = WriterLease::try_acquire(&fixture.root).unwrap();
    let before = writer.read_record().unwrap();
    assert!(!before.is_empty());
    for _ in 0..2 {
        let proof = writer_proof(&journal, &mut writer, &seal.policy, deadline()).unwrap();
        assert_eq!(proof.size, before.len() as u64);
        assert_eq!(
            proof.digest,
            format!("{:x}", Sha256::digest(before.as_bytes()))
        );
        assert_eq!(
            proof.identity,
            platform::identity(&platform::open_file(writer.path()).unwrap()).unwrap()
        );
        assert_eq!(writer.read_record().unwrap(), before);
        assert!(matches!(
            WriterLease::try_acquire(&fixture.root),
            Err(PortError::WriterBusy(_))
        ));
    }
    let other_root = fixture
        ._temp
        .path()
        .canonicalize()
        .unwrap()
        .join("other-data");
    private_root(&other_root);
    let mut other_writer = WriterLease::try_acquire(&other_root).unwrap();
    let other_before = other_writer.read_record().unwrap();
    assert!(matches!(
        writer_proof(&journal, &mut other_writer, &seal.policy, deadline()),
        Err(Reason::IdentityChanged)
    ));
    assert_eq!(other_writer.read_record().unwrap(), other_before);
    assert_eq!(writer.read_record().unwrap(), before);
}

#[cfg(unix)]
#[test]
fn held_writer_proof_rejects_intermediate_handle_after_name_is_restored() {
    use std::os::unix::fs::MetadataExt;

    let fixture = PackageFixture::new(false);
    let (_install, journal) = fixture.journal(true);
    let seal = read_seal(&journal, deadline()).unwrap();
    let mut writer = WriterLease::try_acquire(&fixture.root).unwrap();
    let before = writer.read_record().unwrap();
    let receipt_before = fs::read(journal.receipt_path()).unwrap();
    let state_before = serde_json::to_vec(&journal.state).unwrap();
    let held_identity = platform::identity(&platform::open_file(writer.path()).unwrap()).unwrap();
    let original = fixture.root.join("original-writer");
    let replacement = fixture.root.join("replacement-writer");
    let result = writer_proof_with_open(&journal, &mut writer, &seal.policy, deadline(), |path| {
        // The production path has already validated A and read its record.
        // Open equal-byte B, then restore A before either post-read check.
        fs::rename(path, &original).unwrap();
        private_file(path, before.as_bytes());
        let candidate = platform::open_file(path).unwrap();
        assert_ne!(platform::identity(&candidate).unwrap(), held_identity);
        assert_eq!(candidate.metadata().unwrap().len(), before.len() as u64);
        fs::rename(path, &replacement).unwrap();
        fs::rename(&original, path).unwrap();
        assert_eq!(candidate.metadata().unwrap().nlink(), 1);
        Ok(candidate)
    });
    // Both ordinary name checks see A; only comparing the actual proof handle
    // rejects B. Without that comparison this returns A's digest with B's inode.
    assert!(matches!(result, Err(Reason::IdentityChanged)));
    writer.validate_current(&fixture.root).unwrap();
    assert_eq!(writer.read_record().unwrap(), before);
    assert_eq!(fs::read(&replacement).unwrap(), before.as_bytes());
    assert_eq!(fs::read(journal.receipt_path()).unwrap(), receipt_before);
    assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state_before);
    let contender = platform::open_file(writer.path()).unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(fs::TryLockError::WouldBlock)
    ));
    drop(writer);
    contender.try_lock().unwrap();
}

#[test]
fn immutable_helper_seal_is_manifest_bound_and_private_copy_is_exact() {
    let fixture = PackageFixture::new(true);
    let (_install, journal) = fixture.journal(true);
    let seal = read_seal(&journal, deadline()).unwrap();
    assert_eq!(
        seal.runner.digest,
        journal.state.after_exit.as_ref().unwrap().runner.digest
    );
    let runner = if cfg!(windows) {
        "helper/runner.exe"
    } else {
        "helper/runner"
    };
    assert_eq!(
        fs::read(journal.root.join(runner)).unwrap(),
        b"inert synthetic native application, never executed"
    );
    if cfg!(windows) {
        assert_eq!(
            fs::read(journal.root.join("helper/tail-source.ps1")).unwrap(),
            include_bytes!("../../../scripts/install/package-uninstall.ps1")
        );
    } else {
        // Only Windows needs a PowerShell tail; a Unix runner finishes in-process.
        assert!(seal.tail.is_none() && seal.tail_source.is_none());
        assert!(!journal.root.join("helper/tail-source.ps1").exists());
    }
    private_file(
        &journal.root.join("helper/unknown.log"),
        b"unknown retained",
    );
    assert!(!account_package(&journal, &seal, deadline()).unwrap());
}
#[cfg(windows)]
#[test]
fn historical_package_without_tail_remains_explicitly_pending_with_recovery_image() {
    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let seal = read_seal(&journal, deadline()).unwrap();
    let parent = exit_lock(
        &journal.root,
        &seal.parent_exit,
        &seal.policy,
        deadline(),
        false,
    )
    .unwrap();
    let runner = exit_lock(
        &journal.root,
        &seal.runner_exit,
        &seal.policy,
        deadline(),
        false,
    )
    .unwrap();
    let installation =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    let result = finalize(
        &mut journal,
        &seal,
        &installation,
        &parent,
        &runner,
        deadline(),
    );
    assert!(
        matches!(result, Err(Reason::OwnedAfterExitHelperRequired)),
        "actual result {result:?}; report {}",
        serde_json::to_string(&journal.state.report).unwrap()
    );
    assert!(
        fixture
            .prefix
            .join(agent_session_grep_launcher::metadata::APP_NAME)
            .exists()
    );
    assert!(journal.root.join("helper/runner.exe").exists());
    assert!(fixture.catalog.exists() && SqliteControlStore::path(&fixture.root).exists());
}
#[cfg(unix)]
#[test]
fn unix_package_cleanup_completes_in_process_without_a_tail_helper() {
    use std::cell::Cell;

    for keep in [true, false] {
        let (fixture, mut journal) = package_fixture_for_finalize(keep);
        let receipt_root = journal.root.clone();
        let owner = journal.state.owner.clone();
        let calls = Rc::new(Cell::new(0));
        let observed = Rc::clone(&calls);
        let result = with_completion_pass_hook(
            move |_| {
                observed.set(observed.get() + 1);
                let state = load_state(&receipt_root, &owner, deadline())
                    .unwrap()
                    .unwrap();
                assert!(state.report.cleanup_pending);
                assert!(state.report.after_exit_cleanup_pending);
                assert_eq!(state.report.status, "pending_cleanup");
                assert!(matches!(state.report.outcome(), Outcome::Partial));
            },
            || run_unix_fixture_finalize(&fixture, &mut journal, deadline()),
        );
        assert!(
            result.is_ok(),
            "mode {keep}, actual result {result:?}; report {}",
            serde_json::to_string(&journal.state.report).unwrap()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            journal.state.report.status,
            "complete_with_retained_private_markers"
        );
        assert!(!journal.state.report.cleanup_pending);
        assert!(!journal.state.report.after_exit_cleanup_pending);
        assert!(journal.state.report.reasons.is_empty());
        assert!(matches!(journal.state.report.outcome(), Outcome::Success));
        let persisted = load_state(&journal.root, &journal.state.owner, deadline())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&persisted).unwrap(),
            serde_json::to_vec(&journal.state).unwrap()
        );
        assert!(
            !fixture
                .prefix
                .join(agent_session_grep_launcher::metadata::APP_NAME)
                .exists()
        );
        assert!(!journal.root.join("helper/runner").exists());
        assert_eq!(fixture.catalog.exists(), keep);
        assert_eq!(SqliteControlStore::path(&fixture.root).exists(), keep);
        with_completion_inputs(&fixture, &mut journal, |journal, guards, mode| {
            let mut completed =
                inspect_completed_uninstall(journal, guards, mode, deadline()).unwrap();
            completed.validate_current().unwrap();
        });
    }
}

#[cfg(unix)]
fn run_unix_fixture_finalize(
    fixture: &PackageFixture,
    journal: &mut Journal,
    end: Instant,
) -> Result<(), Reason> {
    let seal = read_seal(journal, end)?;
    let parent = exit_lock(&journal.root, &seal.parent_exit, &seal.policy, end, false)?;
    let runner = exit_lock(&journal.root, &seal.runner_exit, &seal.policy, end, false)?;
    let installation = update_state::acquire_installation_lock(&fixture.prefix, end)
        .map_err(|_| Reason::AfterExitCleanupPending)?;
    finalize(journal, &seal, &installation, &parent, &runner, end)
}

#[cfg(unix)]
fn assert_unix_pending_receipts(journal: &Journal) -> DeferredCleanup {
    let persisted = load_state(&journal.root, &journal.state.owner, deadline())
        .unwrap()
        .unwrap();
    for sequence in 1..=persisted.sequence {
        let bytes = fs::read(journal.root.join(format!("state-{sequence:06}.json"))).unwrap();
        let state: DeferredCleanup = serde_json::from_slice(&bytes).unwrap();
        assert!(state.report.cleanup_pending, "sequence {sequence}");
        assert!(
            state.report.after_exit_cleanup_pending,
            "sequence {sequence}"
        );
        assert_eq!(state.report.status, "pending_cleanup");
        assert!(matches!(state.report.outcome(), Outcome::Partial));
    }
    persisted
}

#[cfg(unix)]
fn assert_unix_finalize_stays_pending(journal: &Journal) {
    let persisted = assert_unix_pending_receipts(journal);
    assert_eq!(
        serde_json::to_vec(&persisted).unwrap(),
        serde_json::to_vec(&journal.state).unwrap()
    );
    // The actual Unix caller removed the runner before reaching preflight.
    assert!(!journal.root.join("helper/runner").exists());
}

#[cfg(unix)]
#[test]
fn unix_finalize_precompletion_refusal_preserves_durable_pending_in_both_modes() {
    for keep in [true, false] {
        let (fixture, mut journal) = package_fixture_for_finalize(keep);
        let first = journal.root.join("state-000001.json");
        let prefix = fixture.prefix.clone();
        let data = fixture.root.clone();
        let observed = Rc::new(RefCell::new(None));
        let snapshot = Rc::clone(&observed);
        let result = with_completion_pass_hook(
            move |_| {
                // Preserve valid JSON and logical history, but change the exact
                // evidence between the two real preflight passes.
                let mut bytes = fs::read(&first).unwrap();
                bytes.push(b'\n');
                fs::write(&first, bytes).unwrap();
                *snapshot.borrow_mut() = Some(cleanup_inventory(&prefix, &data));
            },
            || run_unix_fixture_finalize(&fixture, &mut journal, deadline()),
        );
        assert!(matches!(result, Err(Reason::IdentityChanged)), "{result:?}");
        assert_unix_finalize_stays_pending(&journal);
        assert_eq!(
            borrowed_keep_data_inventory(&fixture),
            *observed.borrow().as_ref().expect("real preflight reached")
        );
    }
}

#[cfg(unix)]
#[test]
fn unix_finalize_original_end_preserves_durable_pending_in_both_modes() {
    for keep in [true, false] {
        let (fixture, mut journal) = package_fixture_for_finalize(keep);
        let prefix = fixture.prefix.clone();
        let data = fixture.root.clone();
        let observed = Rc::new(RefCell::new(None));
        let snapshot = Rc::clone(&observed);
        let started = Instant::now();
        let end = started + Duration::from_secs(2);
        let result = with_completion_pass_hook(
            move |_| {
                *snapshot.borrow_mut() = Some(cleanup_inventory(&prefix, &data));
                std::thread::sleep(
                    end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
            },
            || run_unix_fixture_finalize(&fixture, &mut journal, end),
        );
        let returned = Instant::now();
        assert!(
            matches!(result, Err(Reason::Deadline)),
            "mode {keep}, result {result:?}, elapsed {:?}",
            returned.duration_since(started)
        );
        assert!(Instant::now() >= end);
        assert_unix_pending_receipts(&journal);
        assert!(journal.state.report.cleanup_pending);
        assert!(journal.state.report.after_exit_cleanup_pending);
        let after = borrowed_keep_data_inventory(&fixture);
        if let Some(at_preflight) = observed.borrow().as_ref() {
            assert_unix_finalize_stays_pending(&journal);
            assert_eq!(&after, at_preflight);
        }
        // Expiry may precede preflight on a loaded machine. Preserve that exact
        // partial inventory for recovery. Neither case permits completed
        // receipts or another effect under this same exhausted request end.
        assert_eq!(
            run_unix_fixture_finalize(&fixture, &mut journal, end),
            Err(Reason::Deadline)
        );
        assert_eq!(borrowed_keep_data_inventory(&fixture), after);
        // The production failure path cannot save beyond the old end; its
        // diagnostic only changes memory, while the pending receipt survives.
        let receipt = fs::read(journal.receipt_path()).unwrap();
        journal.state.report.pending(Reason::Deadline);
        journal.save_before_deadline(end).unwrap();
        assert_eq!(fs::read(journal.receipt_path()).unwrap(), receipt);
        assert!(matches!(journal.state.report.outcome(), Outcome::Partial));
    }
}

#[cfg(unix)]
#[test]
fn unix_finalize_precompletion_expiry_preserves_durable_pending_in_both_modes() {
    use std::cell::Cell;

    for keep in [true, false] {
        let (fixture, mut journal) = package_fixture_for_finalize(keep);
        let prefix = fixture.prefix.clone();
        let data = fixture.root.clone();
        let observed = Rc::new(RefCell::new(None));
        let snapshot = Rc::clone(&observed);
        let shortened = Rc::new(Cell::new(None));
        let injected = Rc::clone(&shortened);
        let requested = deadline();
        let result = with_completion_pass_hook(
            move |end| {
                assert_eq!(*end, requested);
                assert!(injected.get().is_none(), "preflight must be reached once");
                *snapshot.borrow_mut() = Some(cleanup_inventory(&prefix, &data));
                // Shorten the real local end only after the actual first
                // preflight pass. The production next-pass check must refuse.
                // This proves the boundary, not a wall-clock performance limit.
                *end = (*end).min(Instant::now());
                injected.set(Some(*end));
            },
            || run_unix_fixture_finalize(&fixture, &mut journal, requested),
        );
        let expired = shortened.get().expect("real preflight must be reached");
        assert!(expired <= requested && Instant::now() >= expired);
        assert_eq!(result, Err(Reason::Deadline), "mode {keep}");
        assert_unix_finalize_stays_pending(&journal);
        assert_eq!(
            borrowed_keep_data_inventory(&fixture),
            *observed.borrow().as_ref().expect("preflight inventory")
        );
        let receipt = fs::read(journal.receipt_path()).unwrap();
        journal.state.report.pending(Reason::Deadline);
        journal.save_before_deadline(expired).unwrap();
        assert_eq!(fs::read(journal.receipt_path()).unwrap(), receipt);
        assert!(matches!(journal.state.report.outcome(), Outcome::Partial));
    }
}

#[cfg(windows)]
fn tail_handoff(fixture: &mut PackageFixture, keep: bool) -> (Journal, Seal) {
    let (install, mut journal) = fixture.journal(keep);
    drop(install);
    if !keep {
        let control = fixture.control.take().unwrap();
        let installation =
            update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
        let operation = id(&journal.state.owner.nonce);
        let intent = RetirementIntent::bind_with_deadline(
            &control,
            &fixture.catalog,
            &fixture.prefix,
            &installation,
            &operation,
            deadline(),
        )
        .unwrap();
        let guards = cleanup_data(&control, &mut journal, Some(&intent), deadline()).unwrap();
        let refreshed = intent
            .refresh_with_deadline(&control, &guards.policy_owner, deadline())
            .unwrap();
        drop(control);
        terminal_handoff(&mut journal, &refreshed, guards.retirement(), deadline()).unwrap();
    }
    let seal = read_seal(&journal, deadline()).unwrap();
    for proof in &seal.metadata.removable {
        if verify(&fixture.root, proof, &seal.policy, deadline(), true).unwrap() {
            remove_exact(&fixture.root, proof, &seal.policy, deadline()).unwrap();
        }
    }
    for proof in &seal.package_files {
        if verify(&fixture.prefix, proof, &seal.policy, deadline(), true).unwrap() {
            remove_exact(&fixture.prefix, proof, &seal.policy, deadline()).unwrap();
        }
    }
    let root = fixture.root.clone();
    let mut plan = journal.state.after_exit.clone().unwrap();
    plan.installation_lock =
        Some(private_proof(&fixture.prefix, INSTALLATION_LOCK, &seal.policy, deadline()).unwrap());
    plan.data_locks.clear();
    for relative in DATA_LOCKS {
        let kind = match *relative {
            "policy-owner.lock" => LockKind::PolicyOwner,
            "policy-emission.lock" => LockKind::PolicyEmission,
            "control-create.lock" => LockKind::ControlCreate,
            "catalog-handles.lock" => LockKind::CatalogHandles,
            "history-readers.lock" => LockKind::HistoryReaders,
            "background.lock" => LockKind::Background,
            "supervisor.lock" => LockKind::Supervisor,
            _ => managed_purge::purge_lock_kind().unwrap(),
        };
        drop(acquire(&root, kind, deadline(), Reason::IdentityChanged).unwrap());
        plan.data_locks
            .push(private_proof(&root, relative, &seal.policy, deadline()).unwrap());
    }
    if keep {
        // The actual runner closes its control connection before capturing the
        // physical retained-file proofs. Closing the last writable WAL handle
        // checkpoints the main image even when the logical policy is unchanged.
        drop(fixture.control.take());
        for relative in [journal.state.owner.catalog_name.as_str(), "control.db"] {
            plan.retained_data
                .push(private_proof(&root, relative, &seal.policy, deadline()).unwrap());
        }
    } else {
        plan.retirement_marker =
            Some(private_proof(&root, RETIREMENT_MARKER, &seal.policy, deadline()).unwrap());
    }
    plan.deadline_tick = Some(deadline_tick(Instant::now() + BUDGET).unwrap());
    plan.payload_complete = true;
    plan.tail_pending = true;
    plan.tail_handoff_sequence = Some(journal.state.sequence + 1);
    journal.state.after_exit = Some(plan);
    journal.state.report.package_cleanup_pending = false;
    journal.state.report.private_metadata_cleanup_pending = false;
    journal.state.report.after_exit_cleanup_pending = true;
    journal.save(deadline()).unwrap();
    (journal, seal)
}
#[cfg(windows)]
#[test]
fn tail_receipt_classification_does_not_turn_recorded_completion_into_live_absence() {
    let mut fixture = PackageFixture::new(true);
    let (journal, seal) = tail_handoff(&mut fixture, true);
    let plan = journal.state.after_exit.as_ref().unwrap();
    let sequence = plan.tail_handoff_sequence.unwrap();
    let receipt_path = journal.root.join(format!("state-{sequence:06}.json"));
    let receipt_bytes = fs::read(&receipt_path).unwrap();
    let before = serde_json::to_vec(&journal.state).unwrap();
    let result_path = journal
        .root
        .join(format!("helper/tail-result-{sequence:06}.json"));
    assert!(
        validated_tail_result(&journal, &seal, sequence, deadline())
            .unwrap()
            .is_none()
    );
    let mut result = json!({
        "schema": "asg.uninstall-tail-result/v1",
        "nonce": journal.state.owner.nonce,
        "seal_sha256": plan.seal.digest,
        "receipt_sequence": sequence,
        "receipt_sha256": format!("{:x}", Sha256::digest(&receipt_bytes)),
        "deadline_tick": plan.deadline_tick.unwrap(),
        "tail_removed": true,
        "runner_removed": false,
        "complete": false,
        "reason": "runner_cleanup_pending"
    });
    private_file(&result_path, &serde_json::to_vec(&result).unwrap());
    assert_eq!(
        validated_tail_result(&journal, &seal, sequence, deadline()).unwrap(),
        Some(TailReceiptCompletion::Pending)
    );
    assert!(
        inspect_tail_completion(&journal, &seal, deadline())
            .unwrap()
            .is_none()
    );
    result["runner_removed"] = json!(true);
    result["complete"] = json!(true);
    result["reason"] = json!("complete");
    let complete_bytes = serde_json::to_vec(&result).unwrap();
    fs::write(&result_path, &complete_bytes).unwrap();
    assert_eq!(
        validated_tail_result(&journal, &seal, sequence, deadline()).unwrap(),
        Some(TailReceiptCompletion::Complete)
    );
    assert!(matches!(
        inspect_tail_completion(&journal, &seal, deadline()),
        Err(Reason::AfterExitCleanupPending)
    ));
    assert_eq!(serde_json::to_vec(&journal.state).unwrap(), before);
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt_bytes);
    assert_eq!(fs::read(&result_path).unwrap(), complete_bytes);
    assert!(journal.root.join(&plan.runner.relative).exists());
    assert!(
        journal
            .root
            .join(&plan.tail.as_ref().unwrap().relative)
            .exists()
    );

    // Even whitespace changes the exact acknowledged receipt bytes. A
    // semantically identical JSON document is not the recorded preimage.
    let mut changed_receipt = receipt_bytes;
    changed_receipt.push(b'\n');
    fs::write(&receipt_path, &changed_receipt).unwrap();
    assert!(matches!(
        validated_tail_result(&journal, &seal, sequence, deadline()),
        Err(Reason::IdentityChanged)
    ));
    assert_eq!(fs::read(&receipt_path).unwrap(), changed_receipt);
    assert_eq!(fs::read(&result_path).unwrap(), complete_bytes);
}

#[cfg(windows)]
fn observed_tail_output(
    script: &Path,
    parameters: serde_json::Value,
) -> (std::process::Output, serde_json::Value) {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let diagnostic = agent_session_grep_testkit::tempdir().unwrap();
    let path = diagnostic.path().join("tail-diagnostic.json");
    // Observe only after the original file returns. Never edit its manifested
    // bytes, replay cleanup, replace its end or emit raw PowerShell errors.
    let observer = r#"
$Error.Clear()
$parameters = @{}
$decoded = ConvertFrom-Json -InputObject $env:ASG_TEST_TAIL_PARAMETERS
foreach ($property in $decoded.PSObject.Properties) { $parameters[$property.Name] = $property.Value }
& $env:ASG_TEST_TAIL_SCRIPT @parameters
$tailExit = $LASTEXITCODE
$records = @()
foreach ($record in @($Error | Select-Object -First 4)) {
    $exceptions = @()
    $exception = $record.Exception
    for ($depth = 0; $null -ne $exception -and $depth -lt 4; $depth++) {
        $native = $null
        if ($exception -is [ComponentModel.Win32Exception]) { $native = $exception.NativeErrorCode }
        $exceptions += [ordered]@{
            hresult = $exception.HResult
            native = $native
            io = $exception -is [IO.IOException]
            security = $exception -is [Security.SecurityException]
        }
        $exception = $exception.InnerException
    }
    $records += [ordered]@{
        line = $record.InvocationInfo.ScriptLineNumber
        offset = $record.InvocationInfo.OffsetInLine
        exceptions = $exceptions
    }
}
try {
    $summary = [ordered]@{ exit = $tailExit; error_count = $Error.Count; records = $records }
    [IO.File]::WriteAllText($env:ASG_TEST_TAIL_DIAGNOSTIC, ($summary | ConvertTo-Json -Depth 6 -Compress))
} catch {}
exit $tailExit
"#;
    let output = Command::new(system_powershell().unwrap())
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            observer,
        ])
        .env("ASG_TEST_TAIL_SCRIPT", script)
        .env("ASG_TEST_TAIL_PARAMETERS", parameters.to_string())
        .env("ASG_TEST_TAIL_DIAGNOSTIC", &path)
        .stdin(Stdio::null())
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    let bytes = fs::read(&path).expect("tail observation unavailable");
    assert!(bytes.len() <= 8192, "tail observation oversized");
    let observation: serde_json::Value =
        serde_json::from_slice(&bytes).expect("tail observation malformed");
    assert_eq!(
        observation["exit"].as_i64(),
        output.status.code().map(i64::from)
    );
    if !output.status.success() {
        eprintln!("tail observation: {observation}");
    }
    (output, observation)
}

#[cfg(windows)]
#[test]
fn tail_observer_preserves_exit_and_streams_after_a_caught_error() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let script = temp.path().join("synthetic.ps1");
    fs::write(
        &script,
        b"param([int]$Value)\ntry { throw 'synthetic error' } catch {}\n[Console]::Out.Write('out'+$Value)\n[Console]::Error.Write('err'+$Value)\nexit 10\n",
    )
    .unwrap();
    let (output, observation) = observed_tail_output(&script, json!({"Value": 7}));
    assert_eq!(output.status.code(), Some(10));
    assert_eq!(output.stdout, b"out7");
    assert_eq!(output.stderr, b"err7");
    assert!(observation["error_count"].as_u64().unwrap() > 0);
    let records = observation["records"].as_array().unwrap();
    assert!(!records.is_empty() && records.len() <= 4);
    let evidence = observation.to_string();
    assert!(!evidence.contains("synthetic error") && !evidence.contains("synthetic.ps1"));
}

#[cfg(windows)]
fn tail_output(journal: &Journal) -> std::process::Output {
    let plan = journal.state.after_exit.as_ref().unwrap();
    observed_tail_output(
        Path::new(
            CanonicalLocator::from_path(&journal.root.join("helper/tail.ps1"))
                .unwrap()
                .as_str(),
        ),
        json!({
            "Prefix": journal.prefix,
            "Catalog": journal.catalog,
            "Nonce": plan.nonce,
            "DeadlineTick": plan.deadline_tick.unwrap(),
            "ReceiptSequence": journal.state.sequence,
            "ReceiptSha256": journal.receipt_digest.as_ref().unwrap(),
            "SealSha256": plan.seal.digest,
        }),
    )
    .0
}
#[cfg(windows)]
#[test]
fn actual_windows_tail_default_deletes_only_exact_planned_helpers_and_consumes_receipt() {
    let mut fixture = PackageFixture::new(true);
    let (mut journal, seal) = tail_handoff(&mut fixture, false);
    let original = fixture._temp.path().join("unrelated-source.jsonl");
    fs::write(&original, b"synthetic original provider bytes\n").unwrap();
    let output = tail_output(&journal);
    assert_eq!(
        output.status.code(),
        Some(0),
        "tail status {:?}; stdout {:?}; stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(
        !journal.root.join("helper/runner.exe").exists()
            && !journal.root.join("helper/tail.ps1").exists()
    );
    assert!(
        journal.root.join("helper/tail-source.ps1").exists()
            && fixture.root.join(RETIREMENT_MARKER).exists()
    );
    let state_before = serde_json::to_vec(&journal.state).unwrap();
    let receipt_before = fs::read(journal.receipt_path()).unwrap();
    let marker_before = fs::read(fixture.root.join(RETIREMENT_MARKER)).unwrap();
    let inspected = inspect_tail_completion(&journal, &seal, deadline())
        .unwrap()
        .unwrap();
    assert!(!inspected.after_exit_cleanup_pending);
    assert!(journal.state.report.after_exit_cleanup_pending);
    assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state_before);
    assert_eq!(fs::read(journal.receipt_path()).unwrap(), receipt_before);
    assert_eq!(
        fs::read(fixture.root.join(RETIREMENT_MARKER)).unwrap(),
        marker_before
    );
    let unknown = journal.root.join("helper/unrelated.json");
    private_file(&unknown, b"unrelated retained bytes");
    assert!(matches!(
        inspect_tail_completion(&journal, &seal, deadline()),
        Err(Reason::UnclassifiedOwnedArtifact)
    ));
    assert_eq!(fs::read(&unknown).unwrap(), b"unrelated retained bytes");
    assert_eq!(fs::read(journal.receipt_path()).unwrap(), receipt_before);
    fs::remove_file(unknown).unwrap();
    assert!(consume_tail_result(&mut journal, &seal, deadline()).unwrap());
    assert_eq!(
        serde_json::to_vec(&journal.state.report).unwrap(),
        serde_json::to_vec(&inspected).unwrap()
    );
    assert!(!journal.state.report.after_exit_cleanup_pending);
    assert!(!fixture.catalog.exists() && !SqliteControlStore::path(&fixture.root).exists());
    assert_eq!(
        fs::read(original).unwrap(),
        b"synthetic original provider bytes\n"
    );
}
#[cfg(windows)]
#[test]
fn actual_windows_tail_keep_data_preserves_catalog_policy_and_exact_deny_snapshot() {
    let mut fixture = PackageFixture::new(true);
    let (mut journal, seal) = tail_handoff(&mut fixture, true);
    let before = SqliteControlStore::open_current_read_only(&fixture.root)
        .unwrap()
        .status()
        .unwrap();
    let catalog = fs::read(&fixture.catalog).unwrap();
    let output = tail_output(&journal);
    assert_eq!(
        output.status.code(),
        Some(0),
        "tail status {:?}; stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let state_before = serde_json::to_vec(&journal.state).unwrap();
    let receipt_before = fs::read(journal.receipt_path()).unwrap();
    let inspected = inspect_tail_completion(&journal, &seal, deadline())
        .unwrap()
        .unwrap();
    assert!(!inspected.after_exit_cleanup_pending);
    assert!(journal.state.report.after_exit_cleanup_pending);
    assert_eq!(serde_json::to_vec(&journal.state).unwrap(), state_before);
    assert_eq!(fs::read(journal.receipt_path()).unwrap(), receipt_before);
    assert_eq!(fs::read(&fixture.catalog).unwrap(), catalog);
    assert!(consume_tail_result(&mut journal, &seal, deadline()).unwrap());
    assert_eq!(
        serde_json::to_vec(&journal.state.report).unwrap(),
        serde_json::to_vec(&inspected).unwrap()
    );
    let control = SqliteControlStore::open_current_read_only(&fixture.root).unwrap();
    assert_eq!(control.status().unwrap(), before);
    assert_eq!(fs::read(&fixture.catalog).unwrap(), catalog);
    assert!(fixture.catalog.exists() && SqliteControlStore::path(&fixture.root).exists());
    assert!(!fixture.root.join(RETIREMENT_MARKER).exists());
}

#[cfg(windows)]
#[test]
fn tail_failed_runner_delete_preserves_recovery_and_rejects_forged_completion() {
    let mut fixture = PackageFixture::new(true);
    let (mut journal, seal) = tail_handoff(&mut fixture, false);
    let plan = journal.state.after_exit.clone().unwrap();
    let runner = package_installation::pinned(&journal.root.join(&plan.runner.relative)).unwrap();
    // The pinned runner is the failure injection. Keep the real tail budget
    // so PowerShell startup and Add-Type cannot consume a shortened deadline
    // before the script removes itself and reaches the locked runner.
    journal.state.after_exit.as_mut().unwrap().deadline_tick =
        Some(deadline_tick(Instant::now() + BUDGET).unwrap());
    journal
        .state
        .after_exit
        .as_mut()
        .unwrap()
        .tail_handoff_sequence = Some(journal.state.sequence + 1);
    journal.save(deadline()).unwrap();
    let output = tail_output(&journal);
    assert_eq!(output.status.code(), Some(10));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(journal.root.join(&plan.runner.relative).exists());
    assert!(journal.root.join("helper/tail-source.ps1").exists());
    assert!(
        !journal.root.join("helper/tail.ps1").exists(),
        "tail must reach runner deletion before the injected lock exhausts its budget"
    );
    assert!(!consume_tail_result(&mut journal, &seal, deadline()).unwrap());
    assert!(
        journal.state.report.after_exit_cleanup_pending
            && journal.state.report.recovery_entry_recorded
    );
    drop(runner);
    let installation =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    // Failed tail already removed itself. The native recovery owner can restore
    // only the exact manifested source bytes; its new inode is written to a new
    // handoff sequence rather than relabeling the old proof.
    let source = seal.tail_source.as_ref().unwrap();
    copy_verified(
        &journal.root,
        source,
        &journal.root,
        "helper/tail.ps1",
        &seal.policy,
        false,
        deadline(),
    )
    .unwrap();
    journal.state.after_exit.as_mut().unwrap().tail =
        Some(private_proof(&journal.root, "helper/tail.ps1", &seal.policy, deadline()).unwrap());
    journal.state.after_exit.as_mut().unwrap().deadline_tick =
        Some(deadline_tick(Instant::now() + BUDGET).unwrap());
    journal
        .state
        .after_exit
        .as_mut()
        .unwrap()
        .tail_handoff_sequence = Some(journal.state.sequence + 1);
    journal.save(deadline()).unwrap();
    drop(installation);
    let output = tail_output(&journal);
    assert_eq!(output.status.code(), Some(0));
    assert!(consume_tail_result(&mut journal, &seal, deadline()).unwrap());
    let result_path = journal.root.join(format!(
        "helper/tail-result-{:06}.json",
        journal
            .state
            .after_exit
            .as_ref()
            .unwrap()
            .tail_handoff_sequence
            .unwrap()
    ));
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&result_path).unwrap()).unwrap();
    value["receipt_sha256"] = json!("0".repeat(64));
    fs::write(&result_path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        validated_tail_result(
            &journal,
            &seal,
            journal
                .state
                .after_exit
                .as_ref()
                .unwrap()
                .tail_handoff_sequence
                .unwrap(),
            deadline()
        )
        .is_err()
    );
}
