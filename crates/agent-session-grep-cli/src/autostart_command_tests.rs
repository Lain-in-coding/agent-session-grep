//! Synthetic managed roots, immutable inert images and injected native manager.
//! No production registry, host configuration, service, or history is touched.
use super::*;
use crate::setup_hosts::ExpectedAsgIdentity;
use agent_session_grep_adapters_sqlite::managed_store::ManagedStore;
use agent_session_grep_launcher::{
    metadata::{self, CurrentPointer, ReleaseMetadata},
    verify_installation,
};
use agent_session_grep_ports::control::{ControlId, ControlStatus};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    prefix: PathBuf,
    catalog: PathBuf,
    location: NativeLocation,
    enabled: Cell<bool>,
    calls: RefCell<Vec<Vec<OsString>>>,
}
impl Fixture {
    fn new(desired: DesiredUpdates) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let root = base.join("private data");
        let control = crate::retry_fixture_busy(|| {
            SqliteControlStore::create(
                &root,
                &ControlId::parse("synthetic-autostart").unwrap(),
                desired,
            )
        });
        let catalog = root.join("catalog.db");
        drop(
            ManagedStore::create(
                &catalog,
                &control,
                ControlId::parse("synthetic-catalog").unwrap(),
                1,
            )
            .unwrap(),
        );
        let directory = base.join("synthetic native");
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join("unrelated.service"),
            b"unrelated user settings",
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            prefix: base.join("package"),
            catalog,
            location: NativeLocation::SystemdUser { directory },
            enabled: Cell::new(false),
            calls: RefCell::new(Vec::new()),
        }
    }
    fn store(&self) -> NativeAutostartStore {
        NativeAutostartStore::open(
            self.location.clone(),
            &journal_root(&self.location, &self.root, "synthetic-autostart"),
            "synthetic-autostart",
        )
        .unwrap()
    }
    fn target(&self) -> PathBuf {
        let NativeLocation::SystemdUser { directory } = &self.location else {
            unreachable!()
        };
        directory.join(self.store().entry_name())
    }
    fn installation(&self, supervisor: bool) -> Installation {
        install(&self.prefix, supervisor)
    }
    fn control(&self) -> SqliteControlStore {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match SqliteControlStore::open_current_read_only(&self.root) {
                Ok(control) => return control,
                Err(PortError::WriterBusy(_)) if std::time::Instant::now() < end => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("synthetic control open failed: {error:?}"),
            }
        }
    }
    fn response(&self, args: &[OsString]) -> LocalCapture {
        let store = self.store();
        if args.iter().any(|arg| arg == "enable") {
            self.enabled.set(true);
        }
        if args.iter().any(|arg| arg == "disable") {
            self.enabled.set(false);
        }
        let registration = self.installation(true);
        let (supervisor, _) = registration.supervisor.as_ref().unwrap();
        let stdout = if args.iter().any(|arg| arg == "LoadUnit") {
            json!({"type":"o","data":["/org/freedesktop/systemd1/unit/synthetic_2eservice"]})
                .to_string()
                .into_bytes()
        } else if args.iter().any(|arg| arg == "ExecStart") {
            json!({"type":"a(sasbttttuii)","data":[[supervisor,[supervisor,"--db",self.catalog],false,0,0,0,0,0,0,0]]}).to_string().into_bytes()
        } else if args.iter().any(|arg| arg == "NeedDaemonReload") {
            [
                json!({"type":"s","data":store.entry_name()}),
                json!({"type":"s","data":self.target()}),
                json!({"type":"as","data":[]}),
                json!({"type":"s","data":"loaded"}),
                json!({"type":"s","data":"inactive"}),
                json!({"type":"s","data":if self.enabled.get(){"enabled"}else{"disabled"}}),
                json!({"type":"b","data":false}),
            ]
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
        } else {
            Vec::new()
        };
        self.calls.borrow_mut().push(args.to_vec());
        LocalCapture {
            success: true,
            stdout,
            stderr: b"private native diagnostics never emitted".to_vec(),
        }
    }
    fn execute(&self, action: Action) -> Summary {
        execute(
            self.catalog.to_str().unwrap(),
            Options {
                action,
                prefix: None,
            },
            Instant::now() + Duration::from_secs(3),
            &mut |_| Ok(self.installation(true)),
            &mut || Ok(self.location.clone()),
            &mut |_, args, _| Ok(self.response(args)),
        )
    }
    fn assert_unrelated(&self) {
        let NativeLocation::SystemdUser { directory } = &self.location else {
            unreachable!()
        };
        assert_eq!(
            fs::read(directory.join("unrelated.service")).unwrap(),
            b"unrelated user settings"
        );
    }
}

fn control_status(control: &SqliteControlStore) -> ControlStatus {
    control
        .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
            control.status()
        })
        .unwrap()
}
fn install(prefix: &Path, supervisor: bool) -> Installation {
    let content = b"inert synthetic immutable image, never executed";
    let hash = format!("{:x}", Sha256::digest(content));
    let dir = format!("versions/{}-{}", env!("CARGO_PKG_VERSION"), &hash[..12]);
    fs::create_dir_all(prefix.join(&dir)).unwrap();
    let app = prefix.join(&dir).join(metadata::APP_NAME);
    let image = prefix.join(&dir).join(if cfg!(windows) {
        "asg-supervisor.exe"
    } else {
        "asg-supervisor"
    });
    if !app.exists() {
        fs::write(&app, content).unwrap();
    }
    if !image.exists() {
        fs::write(&image, content).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&app, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let pointer = json!({"schema":"asg.current/v1","version":env!("CARGO_PKG_VERSION"),"generation":1,
        "dir":dir,"app":metadata::APP_NAME,"app_sha256":hash,"launcher_protocol":1,"activated_at":"2026-10-18T00:00:00Z"});
    let release = json!({"schema":"asg.version/v1","version":env!("CARGO_PKG_VERSION"),"target":metadata::BUILD_TARGET,
        "source_commit":"a".repeat(40),"app_sha256":hash,"catalog_schema":agent_session_grep_adapters_sqlite::SCHEMA_VERSION,"control_schema":1,
        "launcher_protocol_min":1,"launcher_protocol_max":1,"built_at":"2026-10-18T00:00:00Z"});
    let pointer_file = prefix.join("current.json");
    let release_file = prefix.join(&dir).join("release.json");
    if !pointer_file.exists() {
        fs::write(&pointer_file, serde_json::to_vec(&pointer).unwrap()).unwrap();
    }
    if !release_file.exists() {
        fs::write(&release_file, serde_json::to_vec(&release).unwrap()).unwrap();
    }
    let pointer_value = CurrentPointer::parse(&fs::read(&pointer_file).unwrap()).unwrap();
    let release_value =
        ReleaseMetadata::parse(&fs::read(&release_file).unwrap(), &pointer_value).unwrap();
    Installation {
        prefix: prefix.into(),
        pointer: pointer_value,
        release: release_value,
        package_files_sha256: String::new(),
        manifest_sha256: String::new(),
        archive_sha256: String::new(),
        helpers: std::collections::BTreeMap::new(),
        launcher: prefix.join(metadata::APP_NAME),
        expected: ExpectedAsgIdentity {
            version: env!("CARGO_PKG_VERSION").into(),
            launcher_sha256: hash.clone(),
        },
        supervisor: supervisor.then_some((image, hash)),
        _application: verify_installation(prefix).unwrap(),
        _guards: vec![],
        _metadata: vec![],
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}

#[test]
fn parser_is_strict_and_help_does_not_open_or_create_managed_state() {
    for bad in [
        vec!["background", "autostart"],
        vec!["background", "autostart", "toggle"],
        vec!["background", "autostart", "enable", "--install-prefix"],
        vec!["background", "autostart", "enable", "--install-prefix", ""],
        vec![
            "background",
            "autostart",
            "enable",
            "--install-prefix",
            "--help",
        ],
        vec![
            "background",
            "autostart",
            "enable",
            "--install-prefix",
            "x",
            "--install-prefix",
            "y",
        ],
        vec!["background", "autostart", "disable", "extra"],
        vec!["background", "autostart", "disable", "--host", "claude"],
    ] {
        assert!(parse(&args(&bad)).is_err());
    }
    assert_eq!(
        parse(&args(&["background", "autostart", "enable"]))
            .unwrap()
            .action,
        Action::Enable
    );
    let temp = tempfile::tempdir().unwrap();
    let absent = temp.path().join("must remain absent").join("catalog.db");
    assert!(matches!(
        run(
            absent.to_str().unwrap(),
            &args(&["background", "autostart", "--help"]),
            OutputMode::Human,
            None
        ),
        Ok(Outcome::Success)
    ));
    assert!(!absent.parent().unwrap().exists());
}

#[test]
fn missing_managed_state_or_supervisor_is_rejected_before_native_or_binding() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let summary = execute(
        f.catalog.to_str().unwrap(),
        Options {
            action: Action::Enable,
            prefix: None,
        },
        Instant::now() + Duration::from_secs(2),
        &mut |_| Ok(f.installation(false)),
        &mut || Ok(f.location.clone()),
        &mut |_, _, _| panic!("missing shim must not run native commands"),
    );
    assert_eq!(summary.reason, Some(Reason::SupervisorMissing));
    assert!(!summary.installation_bound && !summary.intent_recorded);
    assert!(!f.target().exists());
    assert!(!control_status(&f.control()).autostart_enabled);
    let absent = f.root.join("absent catalog.db");
    let summary = execute(
        absent.to_str().unwrap(),
        Options {
            action: Action::Enable,
            prefix: None,
        },
        Instant::now() + Duration::from_secs(2),
        &mut |_| panic!("missing managed state must precede package verification"),
        &mut || panic!(),
        &mut |_, _, _| panic!(),
    );
    assert_eq!(summary.reason, Some(Reason::ManagedStateUnavailable));
    assert!(!absent.exists());
}

#[test]
fn paused_and_stopped_enable_registers_without_running_and_disable_preserves_intent() {
    for desired in [DesiredUpdates::Paused, DesiredUpdates::Stopped] {
        let f = Fixture::new(desired);
        let enabled = f.execute(Action::Enable);
        assert_eq!(enabled.status, "complete", "reason={:?}", enabled.reason);
        assert!(
            enabled.intent_recorded
                && enabled.private_receipt_recorded
                && enabled.installation_bound
        );
        assert_eq!(enabled.autostart_enabled, Some(true));
        assert_eq!(enabled.registration_present, Some(true));
        assert!(!enabled.manager.as_ref().unwrap().launch_requested);
        assert!(
            f.calls
                .borrow()
                .iter()
                .all(|args| !args.iter().any(|a| a == "start" || a == "--now"))
        );
        assert!(f.target().exists());
        assert!(control_status(&f.control()).autostart_enabled);
        assert_eq!(control_status(&f.control()).desired_updates, desired);
        f.calls.borrow_mut().clear();
        let disabled = f.execute(Action::Disable);
        assert_eq!(disabled.status, "complete", "reason={:?}", disabled.reason);
        assert!(disabled.intent_recorded && disabled.private_receipt_recorded);
        assert_eq!(disabled.autostart_enabled, Some(false));
        assert_eq!(disabled.registration_present, Some(false));
        assert!(!f.target().exists());
        assert!(!control_status(&f.control()).autostart_enabled);
        assert_eq!(control_status(&f.control()).desired_updates, desired);
        let repeated = f.execute(Action::Disable);
        assert_eq!(repeated.status, "complete");
        f.assert_unrelated();
    }
}

#[test]
fn running_enable_uses_manager_start_after_owned_registration_and_latest_gate() {
    let f = Fixture::new(DesiredUpdates::Running);
    let summary = f.execute(Action::Enable);
    assert_eq!(summary.status, "complete", "reason={:?}", summary.reason);
    assert!(summary.manager.as_ref().unwrap().launch_requested);
    assert_eq!(
        f.calls
            .borrow()
            .iter()
            .filter(|args| args.iter().any(|a| a == "start"))
            .count(),
        1
    );
    assert_eq!(
        control_status(&f.control()).desired_updates,
        DesiredUpdates::Running
    );
    assert!(
        !summary.login_verified
            && summary.supervisor_running.is_none()
            && !summary.latest_satisfied
    );
    f.assert_unrelated();
}

#[test]
fn independently_edited_native_configuration_retains_durable_disabled_intent() {
    let f = Fixture::new(DesiredUpdates::Running);
    assert_eq!(f.execute(Action::Enable).status, "complete");
    let user = b"independently edited native registration";
    fs::write(f.target(), user).unwrap();
    f.calls.borrow_mut().clear();
    let result = f.execute(Action::Disable);
    assert_eq!(result.status, "incomplete");
    assert_eq!(result.reason, Some(Reason::NativeConfigurationChanged));
    assert!(result.intent_recorded);
    assert_eq!(result.autostart_enabled, Some(false));
    assert!(!control_status(&f.control()).autostart_enabled);
    assert_eq!(
        control_status(&f.control()).desired_updates,
        DesiredUpdates::Running
    );
    assert_eq!(fs::read(f.target()).unwrap(), user);
    assert!(f.calls.borrow().is_empty());
    f.assert_unrelated();
}

#[test]
fn identical_unowned_registration_is_not_adopted_or_successfully_disabled() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let install = f.installation(true);
    let (image, digest) = install.supervisor.as_ref().unwrap();
    let registration = SupervisorRegistration {
        supervisor: image.clone(),
        supervisor_sha256: digest.clone(),
        catalog: f.catalog.clone(),
    };
    let NativeLocation::SystemdUser { directory } = &f.location else {
        unreachable!()
    };
    let generator = NativeAutostartStore::open(
        f.location.clone(),
        &directory.join(".asg-synthetic-generator"),
        "synthetic-autostart",
    )
    .unwrap();
    generator.enable(&registration, None).unwrap();
    let external = fs::read(f.target()).unwrap();
    let result = f.execute(Action::Enable);
    assert_eq!(result.reason, Some(Reason::RegistrationUnowned));
    assert_eq!(result.owned, Some(false));
    assert!(!result.intent_recorded);
    assert!(f.calls.borrow().is_empty());
    assert_eq!(fs::read(f.target()).unwrap(), external);
    let receipt = f.store().latest_receipt().unwrap().unwrap();
    assert!(!receipt.owned);
    let end = Instant::now() + Duration::from_secs(2);
    let (identity, _) = CommandIdentity::capture(&f.catalog, end).unwrap();
    let live = identity.bind(end).unwrap();
    record_inventory(
        &f.root,
        &live,
        &f.location,
        f.store().journal_root(),
        &receipt,
        end,
    )
    .unwrap();
    let disabled = f.execute(Action::Disable);
    assert_eq!(disabled.status, "incomplete");
    assert_eq!(disabled.reason, Some(Reason::RegistrationUnowned));
    assert!(disabled.intent_recorded);
    assert_eq!(disabled.autostart_enabled, Some(false));
    assert_eq!(fs::read(f.target()).unwrap(), external);
    assert!(f.calls.borrow().is_empty());
    f.assert_unrelated();
}

#[test]
fn original_deadline_and_native_timeout_preserve_partial_completed_stages() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let expired = execute(
        f.catalog.to_str().unwrap(),
        Options {
            action: Action::Enable,
            prefix: None,
        },
        Instant::now(),
        &mut |_| panic!("expired deadline must precede effects"),
        &mut || panic!(),
        &mut |_, _, _| panic!(),
    );
    assert_eq!(expired.reason, Some(Reason::Timeout));
    let end = Instant::now() + Duration::from_secs(2);
    let result = execute(
        f.catalog.to_str().unwrap(),
        Options {
            action: Action::Enable,
            prefix: None,
        },
        end,
        &mut |_| Ok(f.installation(true)),
        &mut || Ok(f.location.clone()),
        &mut |_, _, deadline| {
            assert_eq!(deadline, end);
            Err(native_manager::ErrorCode::Timeout.into())
        },
    );
    assert_eq!(result.status, "incomplete");
    assert_eq!(result.reason, Some(Reason::Timeout));
    assert!(result.intent_recorded && result.private_receipt_recorded);
    assert_eq!(result.autostart_enabled, Some(true));
    assert!(f.target().exists());
    assert_eq!(
        control_status(&f.control()).desired_updates,
        DesiredUpdates::Paused
    );
}

#[test]
fn replacing_physical_root_during_package_verification_never_mutates_new_control() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let old = f.root.with_file_name("original root");
    let result = execute(
        f.catalog.to_str().unwrap(),
        Options {
            action: Action::Enable,
            prefix: None,
        },
        Instant::now() + Duration::from_secs(2),
        &mut |_| {
            let install = f.installation(true);
            fs::rename(&f.root, &old).unwrap();
            let control = crate::retry_fixture_busy(|| {
                SqliteControlStore::create(
                    &f.root,
                    &ControlId::parse("synthetic-replacement").unwrap(),
                    DesiredUpdates::Stopped,
                )
            });
            drop(
                ManagedStore::create(
                    &f.catalog,
                    &control,
                    ControlId::parse("replacement-catalog").unwrap(),
                    1,
                )
                .unwrap(),
            );
            Ok(install)
        },
        &mut || panic!("root changed before choosing user location"),
        &mut |_, _, _| panic!("root changed before native effects"),
    );
    assert_eq!(result.reason, Some(Reason::IdentityChanged));
    assert!(!result.intent_recorded && !result.installation_bound);
    let current = control_status(&f.control());
    assert_eq!(
        current.policy.installation_id.as_str(),
        "synthetic-replacement"
    );
    assert!(!current.autostart_enabled);
    assert_eq!(current.desired_updates, DesiredUpdates::Stopped);
    assert!(!f.target().exists());
}

#[test]
fn summary_never_serializes_native_locators_paths_hashes_or_private_diagnostics() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let summary = f.execute(Action::Enable);
    let json = serde_json::to_string(&summary).unwrap();
    assert!(!json.contains(f.root.to_str().unwrap()));
    assert!(!json.contains(f.prefix.to_str().unwrap()));
    assert!(!json.contains("synthetic-autostart"));
    assert!(!json.contains("diagnostics"));
    assert!(
        !json.contains("sha256") && !json.contains("journal") && !json.contains(r#""receipt":"#)
    );
    assert!(json.contains("private_receipt_recorded"));
}

#[test]
fn late_pause_or_disabled_intent_blocks_launch_and_reports_actual_intent() {
    for paused in [true, false] {
        let f = Fixture::new(DesiredUpdates::Running);
        let mut rechecked = false;
        let result = execute(
            f.catalog.to_str().unwrap(),
            Options {
                action: Action::Enable,
                prefix: None,
            },
            Instant::now() + Duration::from_secs(3),
            &mut |_| Ok(f.installation(true)),
            &mut || Ok(f.location.clone()),
            &mut |_, args, _| {
                let response = f.response(args);
                if !rechecked && args.iter().any(|arg| arg == "ExecStart") {
                    rechecked = true;
                    let control = SqliteControlStore::open_current_writable(&f.root).unwrap();
                    let seq = control_status(&control).policy.control_seq;
                    if paused {
                        control
                            .set_desired_updates(seq, DesiredUpdates::Paused)
                            .unwrap();
                    } else {
                        control.set_autostart_enabled(seq, false).unwrap();
                    }
                }
                Ok(response)
            },
        );
        assert!(rechecked);
        assert!(
            f.calls
                .borrow()
                .iter()
                .all(|args| !args.iter().any(|arg| arg == "start"))
        );
        if paused {
            assert_eq!(result.status, "complete");
            assert_eq!(
                control_status(&f.control()).desired_updates,
                DesiredUpdates::Paused
            );
        } else {
            assert_eq!(result.status, "incomplete");
            assert_eq!(result.reason, Some(Reason::IntentChanged));
            assert_eq!(result.autostart_enabled, Some(false));
        }
    }
}

#[test]
fn transient_policy_owner_contention_completes_within_the_original_deadline() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let (release, released) = std::sync::mpsc::channel();
    let owner =
        crate::retry_fixture_busy(|| ExclusiveGuard::try_acquire(&f.root, LockKind::PolicyOwner));
    let end = Instant::now() + Duration::from_secs(2);
    let finished = std::thread::scope(|threads| {
        let releaser = threads.spawn(move || {
            assert!(released.recv_timeout(Duration::from_secs(2)).is_ok());
            // The guard remains held across the caller's first admission.
            std::thread::sleep(Duration::from_millis(30));
            drop(owner);
        });
        let result = execute(
            f.catalog.to_str().unwrap(),
            Options {
                action: Action::Enable,
                prefix: None,
            },
            end,
            &mut |_| {
                release.send(()).unwrap();
                Ok(f.installation(true))
            },
            &mut || Ok(f.location.clone()),
            &mut |_, args, deadline| {
                assert_eq!(deadline, end);
                Ok(f.response(args))
            },
        );
        releaser.join().unwrap();
        result
    });
    assert_eq!(finished.status, "complete", "reason={:?}", finished.reason);
    assert!(finished.intent_recorded && finished.private_receipt_recorded);
    assert_eq!(
        control_status(&f.control()).desired_updates,
        DesiredUpdates::Paused
    );
    assert!(Instant::now() < end);
    f.assert_unrelated();
}

#[test]
fn persistent_policy_owner_contention_has_no_native_effect_or_recorded_intent() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let owner =
        crate::retry_fixture_busy(|| ExclusiveGuard::try_acquire(&f.root, LockKind::PolicyOwner));
    let result = f.execute(Action::Enable);
    assert_eq!(result.status, "incomplete");
    assert!(matches!(
        result.reason,
        Some(Reason::NativeBusy | Reason::Timeout)
    ));
    assert!(!result.installation_bound && !result.intent_recorded);
    assert!(!result.private_receipt_recorded);
    assert!(!f.target().exists());
    assert!(f.calls.borrow().is_empty());
    assert!(!control_status(&f.control()).autostart_enabled);
    drop(owner);
    f.assert_unrelated();
}

#[test]
fn transient_native_owner_contention_reads_one_verified_receipt_without_rewriting_it() {
    let f = Fixture::new(DesiredUpdates::Paused);
    let installation = f.installation(true);
    let (supervisor, hash) = installation.supervisor.as_ref().unwrap();
    let registration = SupervisorRegistration {
        supervisor: supervisor.clone(),
        supervisor_sha256: hash.clone(),
        catalog: f.catalog.clone(),
    };
    let store = f.store();
    let original = store.enable(&registration, None).unwrap().receipt;
    let guard = store
        .manager_registration(&original, &registration)
        .unwrap();
    let (release, released) = std::sync::mpsc::channel();
    let mut attempts = 0;
    let end = Instant::now() + Duration::from_secs(2);
    let received = std::thread::scope(|threads| {
        let releaser = threads.spawn(move || {
            assert!(released.recv_timeout(Duration::from_secs(2)).is_ok());
            std::thread::sleep(Duration::from_millis(30));
            drop(guard);
        });
        let result = retry_native(end, || {
            attempts += 1;
            if attempts == 1 {
                let busy = store.latest_receipt().unwrap_err();
                assert_eq!(busy.code, crate::native_autostart::ErrorCode::Busy);
                release.send(()).unwrap();
                return Err(busy);
            }
            store.latest_receipt()
        });
        releaser.join().unwrap();
        result
    })
    .unwrap();
    assert!(attempts > 1);
    assert_eq!(received, Some(original));
    assert_eq!(store.inspect_recovery().unwrap().len(), 1);
    assert!(Instant::now() < end);
    f.assert_unrelated();
}

#[test]
fn retry_helpers_never_replay_a_recorded_transaction_or_an_executed_native_call() {
    let end = Instant::now() + Duration::from_secs(1);
    let mut attempts = 0;
    let native = retry_native::<()>(end, || {
        attempts += 1;
        Err(crate::native_autostart::AutostartError {
            code: crate::native_autostart::ErrorCode::Busy,
            transaction_id: Some("synthetic-recorded-operation".into()),
        })
    });
    assert_eq!(native.unwrap_err(), Reason::NativeBusy);
    assert_eq!(attempts, 1);

    let calls = Cell::new(0_usize);
    let mut attempts = 0;
    let manager = retry_manager::<()>(end, &calls, || {
        attempts += 1;
        calls.set(calls.get() + 1);
        Err(native_manager::ErrorCode::Busy.into())
    });
    assert_eq!(manager.unwrap_err().code, native_manager::ErrorCode::Busy);
    assert_eq!(attempts, 1);
    assert_eq!(calls.get(), 1);

    let mut attempts = 0;
    let observed = retry_manager::<()>(end, &Cell::new(0), || {
        attempts += 1;
        Err(ManagerError {
            code: native_manager::ErrorCode::Busy,
            observed: Some(ManagerState {
                registration_present: true,
                manager_loaded: true,
                configured_command_verified: true,
                enabled: Some(true),
                manager_active: None,
                launch_requested: false,
            }),
        })
    })
    .unwrap_err();
    assert!(observed.observed.unwrap().manager_loaded);
    assert_eq!(attempts, 1);

    let mut attempts = 0;
    let expired = retry_native::<()>(Instant::now(), || {
        attempts += 1;
        Ok(())
    });
    assert_eq!(expired.unwrap_err(), Reason::Timeout);
    assert_eq!(attempts, 0);
}

#[test]
fn native_busy_after_callback_returns_partial_once_with_the_recorded_intent() {
    let f = Fixture::new(DesiredUpdates::Running);
    let callbacks = Cell::new(0);
    let end = Instant::now() + Duration::from_secs(2);
    let result = execute(
        f.catalog.to_str().unwrap(),
        Options {
            action: Action::Enable,
            prefix: None,
        },
        end,
        &mut |_| Ok(f.installation(true)),
        &mut || Ok(f.location.clone()),
        &mut |_, _, deadline| {
            assert_eq!(deadline, end);
            callbacks.set(callbacks.get() + 1);
            Err(native_manager::ErrorCode::Busy.into())
        },
    );
    assert_eq!(callbacks.get(), 1);
    assert_eq!(result.reason, Some(Reason::NativeBusy));
    assert!(result.intent_recorded && result.private_receipt_recorded);
    assert!(f.target().exists());
    assert!(control_status(&f.control()).autostart_enabled);
    assert_eq!(f.store().inspect_recovery().unwrap().len(), 1);
    f.assert_unrelated();
}

#[test]
fn live_authority_holds_both_database_lifetimes_and_rechecks_current_intent() {
    let f = Fixture::new(DesiredUpdates::Running);
    let end = Instant::now() + Duration::from_secs(2);
    let (identity, _) = CommandIdentity::capture(&f.catalog, end).unwrap();
    let live = identity.bind(end).unwrap();
    for kind in [LockKind::CatalogHandles, LockKind::ControlHandles] {
        assert!(matches!(
            ExclusiveGuard::try_acquire(&f.root, kind),
            Err(PortError::WriterBusy(_))
        ));
    }
    let control = SqliteControlStore::open_current_writable(&f.root).unwrap();
    let seq = control_status(&control).policy.control_seq;
    control
        .set_desired_updates(seq, DesiredUpdates::Paused)
        .unwrap();
    assert_eq!(
        live.status(end).unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    drop(control);
    drop(live);
    for kind in [LockKind::CatalogHandles, LockKind::ControlHandles] {
        drop(crate::retry_fixture_busy(|| {
            ExclusiveGuard::try_acquire(&f.root, kind.clone())
        }));
    }
}
#[cfg(windows)]
#[test]
fn windows_enable_disable_only_changes_exact_owned_run_value_and_preserves_manual_running() {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::*;
    let f = Fixture::new(DesiredUpdates::Paused);
    let installation = f.installation(true);
    struct RegistryFixture {
        subkey: String,
    }
    impl Drop for RegistryFixture {
        fn drop(&mut self) {
            assert!(
                self.subkey
                    .starts_with(r"Software\AgentSessionGrepAutostartCommandTests\")
            );
            let key: Vec<_> = self.subkey.encode_utf16().chain(Some(0)).collect();
            assert_eq!(
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr()) },
                0
            );
        }
    }
    let mut random = [0; 8];
    getrandom::fill(&mut random).unwrap();
    let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let registry = RegistryFixture {
        subkey: format!(r"Software\AgentSessionGrepAutostartCommandTests\{id}"),
    };
    let key: Vec<_> = registry.subkey.encode_utf16().chain(Some(0)).collect();
    let mut handle = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut handle,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let sibling: Vec<_> = std::ffi::OsStr::new("unrelated synthetic value")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let payload = b"unrelated user binary settings";
    assert_eq!(
        unsafe {
            RegSetValueExW(
                handle,
                sibling.as_ptr(),
                0,
                REG_BINARY,
                payload.as_ptr(),
                payload.len() as u32,
            )
        },
        0
    );
    let location = NativeLocation::WindowsRun {
        subkey: registry.subkey.clone(),
    };
    let enabled = execute(
        f.catalog.to_str().unwrap(),
        Options {
            action: Action::Enable,
            prefix: None,
        },
        Instant::now() + Duration::from_secs(3),
        &mut |_| Ok(f.installation(true)),
        &mut || Ok(location.clone()),
        &mut |_, _, _| panic!("Run registration needs no native CLI"),
    );
    assert_eq!(enabled.status, "complete", "reason={:?}", enabled.reason);
    assert!(!enabled.manager.as_ref().unwrap().launch_requested);
    let writable = SqliteControlStore::open_current_writable(&f.root).unwrap();
    writable
        .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
            let sequence = writable.status()?.policy.control_seq;
            writable.set_desired_updates(sequence, DesiredUpdates::Running)
        })
        .unwrap();
    drop(writable);
    let disabled = execute(
        f.catalog.to_str().unwrap(),
        Options {
            action: Action::Disable,
            prefix: None,
        },
        Instant::now() + Duration::from_secs(3),
        &mut |_| Ok(f.installation(true)),
        &mut || panic!("disable must use persisted NativeLocation"),
        &mut |_, _, _| panic!("disable must not kill or spawn manual worker"),
    );
    assert_eq!(disabled.status, "complete", "reason={:?}", disabled.reason);
    assert_eq!(disabled.autostart_enabled, Some(false));
    assert_eq!(disabled.registration_present, Some(false));
    assert!(!disabled.disable.as_ref().unwrap().stop_requested);
    assert_eq!(
        control_status(&f.control()).desired_updates,
        DesiredUpdates::Running
    );
    let mut size = 128u32;
    let mut kind = 0;
    let mut actual = [0u8; 128];
    assert_eq!(
        unsafe {
            RegQueryValueExW(
                handle,
                sibling.as_ptr(),
                std::ptr::null(),
                &mut kind,
                actual.as_mut_ptr(),
                &mut size,
            )
        },
        0
    );
    assert_eq!(kind, REG_BINARY);
    assert_eq!(&actual[..size as usize], payload);
    assert_eq!(unsafe { RegCloseKey(handle) }, 0);
    drop(installation);
}
