//! Disposable package/private roots only. No production configuration or services.
use super::*;
use agent_session_grep_ports::control::{BackgroundControl, DesiredUpdates};
use serde_json::json;

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
    assert_eq!(platform::identity(&acquired._file).unwrap(), proof.identity);
    assert!(matches!(
        exit_lock(&root, &proof, &policy(), deadline(), false),
        Err(Reason::AfterExitCleanupPending)
    ));
    drop(acquired);
    let reacquired = exit_lock(&root, &proof, &policy(), deadline(), false).unwrap();
    assert_eq!(
        platform::identity(&reacquired._file).unwrap(),
        proof.identity
    );
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
        let app = b"inert synthetic native application, never executed".to_vec();
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
        let installation = control
            .bind_installation(&self.prefix, &install_lock)
            .unwrap();
        journal.state.purge_prerequisite_complete = true;
        fence(control, &installation, &mut journal, deadline()).unwrap();
        journal.save(deadline()).unwrap();
        journal.state.private_metadata =
            classify_private(&install, control, &journal, deadline()).unwrap();
        if keep {
            let guards = cleanup_data(control, &mut journal, None, deadline()).unwrap();
            drop(guards);
        } else {
            let operation = id(&journal.state.owner.nonce);
            let intent = RetirementIntent::bind(
                control,
                &self.catalog,
                &self.prefix,
                &install_lock,
                &operation,
            )
            .unwrap();
            journal.state.retirement_intent_captured = true;
            let guards = cleanup_data(control, &mut journal, Some(&intent), deadline()).unwrap();
            let _ = intent.refresh(control, &guards.policy_owner).unwrap();
            drop(guards);
        }
        journal.save(deadline()).unwrap();
        prepare(&install, &mut journal, deadline()).unwrap();
        (install, journal)
    }
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
    let installation =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    let result = finalize(&mut journal, &seal, &installation, deadline());
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
    let fixture = PackageFixture::new(false);
    let (_install, mut journal) = fixture.journal(true);
    let seal = read_seal(&journal, deadline()).unwrap();
    let installation =
        update_state::acquire_installation_lock(&fixture.prefix, deadline()).unwrap();
    let result = finalize(&mut journal, &seal, &installation, deadline());
    assert!(
        result.is_ok(),
        "actual result {result:?}; report {}",
        serde_json::to_string(&journal.state.report).unwrap()
    );
    assert_eq!(
        journal.state.report.status,
        "complete_with_retained_private_markers"
    );
    assert!(!journal.state.report.cleanup_pending);
    assert!(
        !fixture
            .prefix
            .join(agent_session_grep_launcher::metadata::APP_NAME)
            .exists()
    );
    assert!(!journal.root.join("helper/runner").exists());
    // Keep-data cleanup removes package bytes only.
    assert!(fixture.catalog.exists() && SqliteControlStore::path(&fixture.root).exists());
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
        let intent = RetirementIntent::bind(
            &control,
            &fixture.catalog,
            &fixture.prefix,
            &installation,
            &operation,
        )
        .unwrap();
        let guards = cleanup_data(&control, &mut journal, Some(&intent), deadline()).unwrap();
        let refreshed = intent.refresh(&control, &guards.policy_owner).unwrap();
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
