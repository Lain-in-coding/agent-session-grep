//! Isolated user-PATH fixture tests; no daily environment is edited.
use super::*;

use crate::setup_hosts::ExpectedAsgIdentity;
use agent_session_grep_adapters_sqlite::{
    control::SqliteControlStore, managed_store::ManagedStore,
};
use agent_session_grep_launcher::{
    metadata::{self, CurrentPointer, ReleaseMetadata},
    verify_installation,
};
use agent_session_grep_ports::control::{ControlId, DesiredUpdates};
use serde_json::json;

const FIXTURE_BUDGET: Duration = Duration::from_secs(10);

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    prefix: PathBuf,
    catalog: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let root = base.join("managed data");
        let control = crate::retry_fixture_busy(|| {
            SqliteControlStore::create(
                &root,
                &ControlId::parse("synthetic-path").unwrap(),
                DesiredUpdates::Paused,
            )
        });
        let catalog = root.join("catalog.db");
        drop(
            ManagedStore::create(
                &catalog,
                &control,
                ControlId::parse("path-catalog").unwrap(),
                1,
            )
            .unwrap(),
        );
        Self {
            _temp: temp,
            root,
            prefix: base.join("package Unicode 空格"),
            catalog,
        }
    }
    fn installation(&self) -> Installation {
        install(&self.prefix)
    }
    fn binding(&self, location: Location) -> Binding {
        self.installation();
        Binding {
            schema: "asg.user-path-binding/v1".into(),
            installation: "synthetic-path".into(),
            root_identity: RootIdentity::read(&self.root)
                .unwrap()
                .control_id()
                .as_str()
                .into(),
            prefix_identity: RootIdentity::read(&self.prefix)
                .unwrap()
                .control_id()
                .as_str()
                .into(),
            prefix: self.prefix.clone(),
            location,
        }
    }
    fn run(
        &self,
        action: Action,
        location: Location,
        paths: Vec<PathBuf>,
        hook: &mut dyn FnMut(Point) -> Result<()>,
    ) -> PathReport {
        perform(
            &self.catalog,
            Options {
                action,
                prefix: Some(self.prefix.clone()),
            },
            Instant::now() + FIXTURE_BUDGET,
            &mut |_| Ok(self.installation()),
            &mut || {
                Ok(Environment {
                    location: location.clone(),
                    paths: paths.clone(),
                })
            },
            hook,
        )
    }
}
fn install(prefix: &Path) -> Installation {
    let content = b"inert synthetic immutable command image";
    let hash = digest(content);
    let dir = format!("versions/{}-{}", env!("CARGO_PKG_VERSION"), &hash[..12]);
    fs::create_dir_all(prefix.join(&dir)).unwrap();
    let app = prefix.join(&dir).join(metadata::APP_NAME);
    if !app.exists() {
        fs::write(&app, content).unwrap();
    }
    for name in [
        metadata::APP_NAME,
        if cfg!(windows) { "asg.exe" } else { "asg" },
    ] {
        let path = prefix.join(name);
        if !path.exists() {
            fs::write(&path, content).unwrap();
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&app, &prefix.join(metadata::APP_NAME), &prefix.join("asg")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let pointer = json!({"schema":"asg.current/v1","version":env!("CARGO_PKG_VERSION"),"generation":1,"dir":dir,"app":metadata::APP_NAME,"app_sha256":hash,"launcher_protocol":1,"activated_at":"2026-10-18T00:00:00Z"});
    let release = json!({"schema":"asg.version/v1","version":env!("CARGO_PKG_VERSION"),"target":metadata::BUILD_TARGET,"source_commit":"a".repeat(40),"app_sha256":hash,"catalog_schema":agent_session_grep_adapters_sqlite::SCHEMA_VERSION,"control_schema":1,"launcher_protocol_min":1,"launcher_protocol_max":1,"built_at":"2026-10-18T00:00:00Z"});
    let pointer_file = prefix.join("current.json");
    let release_file = prefix.join(&dir).join("release.json");
    if !pointer_file.exists() {
        fs::write(&pointer_file, serde_json::to_vec(&pointer).unwrap()).unwrap();
    }
    if !release_file.exists() {
        fs::write(&release_file, serde_json::to_vec(&release).unwrap()).unwrap();
    }
    let pointer = CurrentPointer::parse(&fs::read(&pointer_file).unwrap()).unwrap();
    let release = ReleaseMetadata::parse(&fs::read(&release_file).unwrap(), &pointer).unwrap();
    Installation {
        prefix: prefix.into(),
        pointer,
        release,
        package_files_sha256: String::new(),
        manifest_sha256: String::new(),
        archive_sha256: String::new(),
        helpers: std::collections::BTreeMap::new(),
        launcher: prefix.join(metadata::APP_NAME),
        expected: ExpectedAsgIdentity {
            version: env!("CARGO_PKG_VERSION").into(),
            launcher_sha256: hash,
        },
        supervisor: None,
        _application: verify_installation(prefix).unwrap(),
        _guards: vec![],
        _metadata: vec![],
    }
}
fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
#[test]
fn strict_parser_help_and_expired_request_have_no_environment_or_state_effect() {
    for bad in [
        vec!["path"],
        vec!["path", "add"],
        vec!["path", "install", "--install-prefix"],
        vec!["path", "install", "--install-prefix", "--help"],
        vec!["path", "remove", "other"],
        vec![
            "path",
            "install",
            "--install-prefix",
            "x",
            "--install-prefix",
            "y",
        ],
    ] {
        assert!(parse(&words(&bad)).is_err());
    }
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let absent = temp.path().join("absent/catalog.db");
    assert!(matches!(
        run(
            absent.to_str().unwrap(),
            &words(&["path", "--help"]),
            OutputMode::Human,
            None
        ),
        Ok(Outcome::Success)
    ));
    assert!(!absent.parent().unwrap().exists());
    let report = perform(
        &absent,
        Options {
            action: Action::Install,
            prefix: None,
        },
        Instant::now(),
        &mut |_| panic!(),
        &mut || panic!(),
        &mut |_| panic!(),
    );
    assert_eq!(report.reason, Some(PathReason::Timeout));
    assert!(!absent.parent().unwrap().exists());
}
#[test]
fn raw_windows_path_preserves_kind_expansion_and_separator_on_remove() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let prefix = temp.path().join("Unicode 空格 prefix");
    for text in [
        "%SYNTHETIC_ROOT%\\bin;unrelated",
        "%SYNTHETIC_ROOT%\\bin;unrelated;",
        "",
    ] {
        let before = Some(path_image(text, true, 2));
        let (after, owned, separator) =
            windows_edit(&prefix, Action::Install, &before, None).unwrap();
        assert!(owned);
        let receipt = Receipt {
            schema: "asg.user-path-receipt/v1".into(),
            id: "a".repeat(32),
            previous: None,
            owned: true,
            present: true,
            kind: Some(2),
            added_separator: separator,
            original_absent: false,
        };
        let (restored, owned, _) =
            windows_edit(&prefix, Action::Remove, &after, Some(&receipt)).unwrap();
        assert!(owned);
        assert!(restored == before);
        let (value, terminated, kind) = raw_path(&after).unwrap();
        assert!(value.starts_with(text));
        assert!(terminated);
        assert_eq!(kind, 2);
    }
    let before = Some(path_image(prefix.to_str().unwrap(), true, 1));
    let (after, owned, _) = windows_edit(&prefix, Action::Install, &before, None).unwrap();
    assert!(!owned);
    assert!(after == before);
    let malformed = Some(Image {
        kind: 3,
        bytes: vec![0, 0],
    });
    assert_eq!(raw_path(&malformed).err(), Some(PathReason::Malformed));
}
#[test]
fn command_conflict_does_not_replace_or_shadow_unowned_binary() {
    let f = Fixture::new();
    f.installation();
    let directory = f.root.join("other tools");
    fs::create_dir(&directory).unwrap();
    let command = directory.join(if cfg!(windows) { "asg.exe" } else { "asg" });
    fs::write(&command, b"unowned command").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert_eq!(
        check_commands(
            &[directory],
            &f.prefix,
            RootIdentity::read(&f.prefix).unwrap(),
            Instant::now() + Duration::from_secs(1)
        )
        .err(),
        Some(PathReason::CommandConflict)
    );
    assert_eq!(fs::read(command).unwrap(), b"unowned command");
    assert!(
        check_commands(
            std::slice::from_ref(&f.prefix),
            &f.prefix,
            RootIdentity::read(&f.prefix).unwrap(),
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap()
    );
}
#[test]
fn independently_changed_owned_fragment_is_not_claimed_removed() {
    let f = Fixture::new();
    let mut binding = f.binding(Location::Windows {
        subkey: "synthetic".into(),
    });
    let prior = Receipt {
        schema: "asg.user-path-receipt/v1".into(),
        id: "a".repeat(32),
        previous: None,
        owned: true,
        present: true,
        kind: Some(2),
        added_separator: true,
        original_absent: false,
    };
    let changed = Some(path_image("independent edited entry", true, 2));
    assert_eq!(
        windows_edit(&f.prefix, Action::Remove, &changed, Some(&prior)).err(),
        Some(PathReason::ConfigurationChanged)
    );
    // The pure Unix-profile regression needs a Unix prefix on every host.
    binding.prefix = PathBuf::from("/synthetic/Unicode 空格");
    let profile = Some(Image {
        kind: 0,
        bytes: b"# user rewrote an owned block with new settings\n".to_vec(),
    });
    assert_eq!(
        profile_edit(&binding, Action::Remove, &profile, Some(&prior)).err(),
        Some(PathReason::ConfigurationChanged)
    );
}
#[test]
fn profile_fragment_quotes_unicode_and_shell_metacharacters_without_eval() {
    let f = Fixture::new();
    let mut binding = f.binding(Location::Windows {
        subkey: "synthetic".into(),
    });
    binding.prefix = PathBuf::from("/synthetic/Unicode 空格 ' $(not-executed) &");
    let block = fragment(&binding).unwrap();
    let text = std::str::from_utf8(&block).unwrap();
    assert!(text.contains("'\\''"));
    assert!(!text.contains("eval"));
    let before = Some(Image {
        kind: 0,
        bytes: b"# original shell settings\n".to_vec(),
    });
    let (after, owned, _) = profile_edit(&binding, Action::Install, &before, None).unwrap();
    assert!(owned);
    let receipt = Receipt {
        schema: "asg.user-path-receipt/v1".into(),
        id: "b".repeat(32),
        previous: None,
        owned: true,
        present: true,
        kind: Some(0),
        added_separator: false,
        original_absent: false,
    };
    let mut current = after.unwrap();
    current
        .bytes
        .extend_from_slice(b"# later independent settings\n");
    let (removed, _, _) =
        profile_edit(&binding, Action::Remove, &Some(current), Some(&receipt)).unwrap();
    assert_eq!(
        removed.unwrap().bytes,
        b"# original shell settings\n# later independent settings\n"
    );
}
#[cfg(windows)]
mod registry {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::System::Registry::*;
    pub(super) struct Fixture {
        pub(super) subkey: String,
        key: HKEY,
    }
    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 8];
            getrandom::fill(&mut random).unwrap();
            let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let subkey = format!(r"Software\AgentSessionGrepPathCommandTests\{id}");
            let name: Vec<_> = subkey.encode_utf16().chain(Some(0)).collect();
            let mut key = ptr::null_mut();
            assert_eq!(
                unsafe {
                    RegCreateKeyExW(
                        HKEY_CURRENT_USER,
                        name.as_ptr(),
                        0,
                        ptr::null(),
                        0,
                        KEY_ALL_ACCESS,
                        ptr::null(),
                        &mut key,
                        ptr::null_mut(),
                    )
                },
                0
            );
            Self { subkey, key }
        }
        fn set(&self, value: &str, kind: u32) {
            let image = path_image(value, true, kind);
            self.set_raw(&image);
        }
        fn set_raw(&self, image: &Image) {
            let name: Vec<_> = "Path".encode_utf16().chain(Some(0)).collect();
            assert_eq!(
                unsafe {
                    RegSetValueExW(
                        self.key,
                        name.as_ptr(),
                        0,
                        image.kind,
                        image.bytes.as_ptr(),
                        image.bytes.len() as u32,
                    )
                },
                0
            );
        }
        fn location(&self) -> Location {
            Location::Windows {
                subkey: self.subkey.clone(),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(
                self.subkey
                    .starts_with(r"Software\AgentSessionGrepPathCommandTests\")
            );
            unsafe {
                RegCloseKey(self.key);
            }
            let name: Vec<_> = self.subkey.encode_utf16().chain(Some(0)).collect();
            assert_eq!(
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, name.as_ptr()) },
                0
            );
        }
    }
    #[test]
    fn registry_install_repeat_remove_preserves_raw_kind_and_independent_entries() {
        let f = super::Fixture::new();
        let registry = Fixture::new();
        let original = path_image("%SYNTHETIC_ROOT%\\bin;unrelated", true, REG_EXPAND_SZ);
        registry.set_raw(&original);
        let report = f.run(
            Action::Install,
            registry.location(),
            vec![],
            &mut |_| Ok(()),
        );
        assert_eq!(report.status, "complete", "reason={:?}", report.reason);
        assert_eq!(report.owned, Some(true));
        assert!(report.changed && report.private_receipt_recorded);
        let installed = windows::read(&registry.subkey).unwrap().unwrap();
        let (text, _, kind) = raw_path(&Some(installed.clone())).unwrap();
        assert!(text.starts_with("%SYNTHETIC_ROOT%\\bin;unrelated;"));
        assert_eq!(kind, REG_EXPAND_SZ);
        let repeat = f.run(
            Action::Install,
            registry.location(),
            vec![],
            &mut |_| Ok(()),
        );
        assert_eq!(repeat.status, "complete");
        assert!(!repeat.changed);
        registry.set(&format!("{text};independent later path"), REG_EXPAND_SZ);
        let removed = f.run(Action::Remove, registry.location(), vec![], &mut |_| Ok(()));
        assert_eq!(removed.status, "complete", "reason={:?}", removed.reason);
        assert_eq!(removed.registration_present, Some(false));
        assert!(removed.changed);
        let actual = windows::read(&registry.subkey).unwrap();
        let (actual, _, kind) = raw_path(&actual).unwrap();
        assert_eq!(
            actual,
            "%SYNTHETIC_ROOT%\\bin;unrelated;independent later path"
        );
        assert_eq!(kind, REG_EXPAND_SZ);
        let repeat = f.run(Action::Remove, registry.location(), vec![], &mut |_| Ok(()));
        assert_eq!(repeat.status, "complete");
        assert!(!repeat.changed);
        assert_eq!(
            SqliteControlStore::open_current_read_only(&f.root)
                .unwrap()
                .status()
                .unwrap()
                .desired_updates,
            DesiredUpdates::Paused
        );
    }
    #[test]
    fn same_preexisting_path_is_unowned_and_never_removed() {
        let f = super::Fixture::new();
        f.installation();
        let registry = Fixture::new();
        registry.set(f.prefix.to_str().unwrap(), REG_SZ);
        let report = f.run(
            Action::Install,
            registry.location(),
            vec![],
            &mut |_| Ok(()),
        );
        assert_eq!(report.status, "complete");
        assert_eq!(report.owned, Some(false));
        assert!(!report.changed);
        let before = windows::read(&registry.subkey).unwrap();
        let report = f.run(Action::Remove, registry.location(), vec![], &mut |_| Ok(()));
        assert_eq!(report.reason, Some(PathReason::Unowned));
        assert_eq!(report.status, "incomplete");
        assert!(windows::read(&registry.subkey).unwrap() == before);
    }
    #[test]
    fn lost_ack_at_native_boundaries_recovers_only_with_durable_transaction_proof() {
        for point in [Point::Prepared, Point::Applied, Point::Verified] {
            let f = super::Fixture::new();
            let registry = Fixture::new();
            registry.set("raw expansion %SYNTHETIC_ROOT%", REG_EXPAND_SZ);
            let mut hit = false;
            let first = f.run(Action::Install, registry.location(), vec![], &mut |at| {
                if at == point && !hit {
                    hit = true;
                    Err(PathReason::Io)
                } else {
                    Ok(())
                }
            });
            assert!(hit);
            assert_eq!(first.status, "incomplete");
            let recovered = f.run(
                Action::Install,
                registry.location(),
                vec![],
                &mut |_| Ok(()),
            );
            assert_eq!(
                recovered.status, "complete",
                "reason={:?}",
                recovered.reason
            );
            assert_eq!(recovered.owned, Some(true));
            assert!(!recovered.changed);
            assert_eq!(
                f.run(Action::Remove, registry.location(), vec![], &mut |_| Ok(()))
                    .status,
                "complete"
            );
            assert_eq!(
                raw_path(&windows::read(&registry.subkey).unwrap())
                    .unwrap()
                    .0,
                "raw expansion %SYNTHETIC_ROOT%"
            );
        }
    }
    #[test]
    fn transaction_racing_external_write_never_reports_success_and_preserves_external_value() {
        let f = super::Fixture::new();
        let registry = Fixture::new();
        registry.set("original", REG_EXPAND_SZ);
        let mut external = false;
        let report = f.run(Action::Install, registry.location(), vec![], &mut |at| {
            if at == Point::Prepared && !external {
                external = true;
                registry.set("independent racing edit", REG_SZ);
            }
            Ok(())
        });
        assert!(external);
        assert_eq!(report.status, "incomplete");
        assert_eq!(report.reason, Some(PathReason::ConfigurationChanged));
        assert_eq!(
            raw_path(&windows::read(&registry.subkey).unwrap())
                .unwrap()
                .0,
            "independent racing edit"
        );
        let report = f.run(Action::Remove, registry.location(), vec![], &mut |_| Ok(()));
        assert_eq!(report.status, "incomplete");
        assert_eq!(
            raw_path(&windows::read(&registry.subkey).unwrap())
                .unwrap()
                .0,
            "independent racing edit"
        );
    }
    #[test]
    fn changed_owned_entry_or_value_kind_is_preserved_and_reported_partial() {
        let f = super::Fixture::new();
        let registry = Fixture::new();
        registry.set("original", REG_EXPAND_SZ);
        assert_eq!(
            f.run(
                Action::Install,
                registry.location(),
                vec![],
                &mut |_| Ok(())
            )
            .status,
            "complete"
        );
        let installed = raw_path(&windows::read(&registry.subkey).unwrap())
            .unwrap()
            .0;
        registry.set(&installed, REG_SZ);
        let report = f.run(Action::Remove, registry.location(), vec![], &mut |_| Ok(()));
        assert_eq!(report.reason, Some(PathReason::ConfigurationChanged));
        assert_eq!(
            raw_path(&windows::read(&registry.subkey).unwrap())
                .unwrap()
                .2,
            REG_SZ
        );
    }
    #[test]
    fn root_replaced_during_package_check_rejects_before_path_mutation() {
        let f = super::Fixture::new();
        let registry = Fixture::new();
        registry.set("original", REG_SZ);
        let old = f.root.with_file_name("old root");
        let report = perform(
            &f.catalog,
            Options {
                action: Action::Install,
                prefix: Some(f.prefix.clone()),
            },
            Instant::now() + Duration::from_secs(3),
            &mut |_| {
                let install = f.installation();
                fs::rename(&f.root, &old).unwrap();
                let control = crate::retry_fixture_busy(|| {
                    SqliteControlStore::create(
                        &f.root,
                        &ControlId::parse("replacement-path").unwrap(),
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
            &mut || panic!("replacement root must be rejected before environment"),
            &mut |_| Ok(()),
        );
        assert_eq!(report.reason, Some(PathReason::IdentityChanged));
        assert_eq!(
            raw_path(&windows::read(&registry.subkey).unwrap())
                .unwrap()
                .0,
            "original"
        );
        assert!(!f.root.join("user-path").exists());
    }

    #[test]
    fn read_only_inventory_binds_root_installation_epoch_and_never_recovers_pending_native_change()
    {
        let f = super::Fixture::new();
        let registry = Fixture::new();
        registry.set("private settings expansion %SYNTHETIC_ROOT%", REG_EXPAND_SZ);
        let mut hit = false;
        let report = f.run(Action::Install, registry.location(), vec![], &mut |point| {
            if point == Point::Applied && !hit {
                hit = true;
                Err(PathReason::Io)
            } else {
                Ok(())
            }
        });
        assert!(hit);
        assert_eq!(report.status, "incomplete");
        let status = SqliteControlStore::open_current_read_only(&f.root)
            .unwrap()
            .status()
            .unwrap();
        let before = windows::read(&registry.subkey).unwrap();
        let inventory = inspect_owned_artifacts(
            &f.root,
            RootIdentity::read(&f.root).unwrap(),
            &status.policy.installation_id,
            status.policy.policy_epoch,
            Instant::now() + FIXTURE_BUDGET,
        )
        .unwrap();
        assert_eq!(inventory.installation, status.policy.installation_id);
        assert!(inventory.root == RootIdentity::read(&f.root).unwrap());
        assert_eq!(inventory.policy_epoch, status.policy.policy_epoch);
        assert_eq!(inventory.operations, 1);
        assert_eq!(inventory.pending_operations, 1);
        assert!(!inventory.settings_conflicts);
        assert!(inventory.artifacts.iter().any(|artifact| artifact.class
            == PathArtifactClass::SettingsImage
            && artifact.asg_owned_container
            && artifact.matches_recorded_digest));
        assert!(
            inventory
                .artifacts
                .iter()
                .all(|artifact| artifact.sha256.len() == 64 && artifact.size_bytes > 0)
        );
        assert!(
            inventory
                .artifacts
                .iter()
                .all(|artifact| artifact.locator.starts_with(f.root.join("user-path")))
        );
        assert!(windows::read(&registry.subkey).unwrap() == before);
        let bad = PolicyEpoch::new(status.policy.policy_epoch.get() + 1).unwrap();
        assert_eq!(
            inspect_owned_artifacts(
                &f.root,
                RootIdentity::read(&f.root).unwrap(),
                &status.policy.installation_id,
                bad,
                Instant::now() + FIXTURE_BUDGET
            )
            .err(),
            Some(PathReason::IdentityChanged)
        );
        assert!(
            !fs::read_dir(f.root.join("user-path"))
                .unwrap()
                .filter_map(|entry| entry.ok())
                .any(|entry| entry.path().join("receipt.json").exists())
        );
    }
    #[test]
    fn path_report_contains_no_path_value_binding_or_private_image_content() {
        let f = super::Fixture::new();
        let registry = Fixture::new();
        registry.set("private expansion %SYNTHETIC_ROOT%", REG_EXPAND_SZ);
        let report = f.run(
            Action::Install,
            registry.location(),
            vec![],
            &mut |_| Ok(()),
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(f.root.to_str().unwrap()));
        assert!(!json.contains(f.prefix.to_str().unwrap()));
        assert!(!json.contains("private expansion"));
        assert!(
            !json.contains("sha256")
                && !json.contains("synthetic-path")
                && !json.contains("subkey")
        );
    }
}
#[cfg(unix)]
mod shell {
    use super::*;
    fn location(f: &Fixture) -> Location {
        let home = f.root.parent().unwrap().join("synthetic home");
        fs::create_dir(&home).unwrap();
        let shell = home.join("bash");
        fs::write(&shell, b"inert shell selection image").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&shell, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(home.join(".bash_profile"), b"# unrelated shell settings\n").unwrap();
        unix::select_at(home, shell).unwrap()
    }
    #[test]
    fn unix_profile_swap_preserves_unrelated_edits_and_owned_exact_removal() {
        let f = Fixture::new();
        let location = location(&f);
        let Location::Unix { profile, .. } = &location else {
            unreachable!()
        };
        let report = f.run(Action::Install, location.clone(), vec![], &mut |_| Ok(()));
        assert_eq!(report.status, "complete", "reason={:?}", report.reason);
        let original = fs::read(profile).unwrap();
        let mut later = original.clone();
        later.extend_from_slice(b"# independent later setting\n");
        fs::write(profile, &later).unwrap();
        let removed = f.run(Action::Remove, location.clone(), vec![], &mut |_| Ok(()));
        assert_eq!(removed.status, "complete", "reason={:?}", removed.reason);
        assert_eq!(
            fs::read(profile).unwrap(),
            b"# unrelated shell settings\n# independent later setting\n"
        );
    }
    #[test]
    fn unix_displaced_race_is_retained_and_never_blindly_restored_over_user_state() {
        let f = Fixture::new();
        let location = location(&f);
        let Location::Unix { profile, .. } = &location else {
            unreachable!()
        };
        let report = f.run(Action::Install, location.clone(), vec![], &mut |at| {
            if at == Point::Prepared {
                fs::write(profile, b"third party changed shell profile\n").unwrap();
            }
            Ok(())
        });
        assert_eq!(report.status, "incomplete");
        assert_eq!(report.reason, Some(PathReason::ConfigurationChanged));
        assert_eq!(
            fs::read(profile).unwrap(),
            b"third party changed shell profile\n"
        );
    }
    #[test]
    fn unknown_shell_and_missing_actual_profile_are_explicit_partial_prerequisites() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let shell = home.join("unknown-shell");
        fs::write(&shell, b"inert").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&shell, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            unix::select_at(home.clone(), shell).err(),
            Some(PathReason::ShellUnavailable)
        );
        let shell = home.join("bash");
        fs::write(&shell, b"inert").unwrap();
        fs::set_permissions(&shell, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            unix::select_at(home, shell).err(),
            Some(PathReason::ProfileUnavailable)
        );
    }
    #[test]
    fn unix_real_bash_fragment_is_literal_and_keeps_exact_path_after_source() {
        let f = Fixture::new();
        let location = location(&f);
        let mut binding = f.binding(location);
        binding.prefix = f
            .root
            .parent()
            .unwrap()
            .join("literal Unicode 空格 ' $(must-not-execute) &");
        let script = f.root.join("literal-fragment.sh");
        fs::write(&script, fragment(&binding).unwrap()).unwrap();
        let bash = Path::new("/usr/bin/bash");
        assert!(bash.is_file());
        let output = std::process::Command::new(bash)
            .arg("--noprofile")
            .arg("--norc")
            .arg("-c")
            .arg(". \"$1\"; printf '%s' \"$PATH\"")
            .arg("fixture")
            .arg(&script)
            .env("PATH", "/synthetic/base")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("/synthetic/base:{}", binding.prefix.display())
        );
    }
    #[test]
    fn unix_lost_native_ack_recovers_pinned_displaced_identity_and_repeat_is_idempotent() {
        for boundary in [Point::Prepared, Point::Applied, Point::Verified] {
            let f = Fixture::new();
            let location = location(&f);
            let mut hit = false;
            let first = f.run(Action::Install, location.clone(), vec![], &mut |point| {
                if point == boundary && !hit {
                    hit = true;
                    Err(PathReason::Io)
                } else {
                    Ok(())
                }
            });
            assert!(hit);
            assert_eq!(first.status, "incomplete");
            let retry = f.run(Action::Install, location.clone(), vec![], &mut |_| Ok(()));
            assert_eq!(retry.status, "complete", "reason={:?}", retry.reason);
            assert_eq!(retry.owned, Some(true));
            assert!(!retry.changed);
            assert_eq!(
                f.run(Action::Remove, location.clone(), vec![], &mut |_| Ok(()))
                    .status,
                "complete"
            );
        }
    }
    #[test]
    fn unix_retained_old_handle_edit_blocks_next_remove_without_overwriting_live_profile() {
        let f = Fixture::new();
        let location = location(&f);
        let Location::Unix { profile, .. } = &location else {
            unreachable!()
        };
        let mut retained = fs::OpenOptions::new().write(true).open(profile).unwrap();
        let installed = f.run(Action::Install, location.clone(), vec![], &mut |_| Ok(()));
        assert_eq!(installed.status, "complete");
        let live = fs::read(profile).unwrap();
        use std::io::{Seek, SeekFrom, Write};
        retained.seek(SeekFrom::Start(0)).unwrap();
        retained
            .write_all(b"retained independent writer changed old image")
            .unwrap();
        retained.sync_all().unwrap();
        let removed = f.run(Action::Remove, location.clone(), vec![], &mut |_| Ok(()));
        assert_eq!(removed.status, "incomplete");
        assert_eq!(removed.reason, Some(PathReason::ConfigurationChanged));
        assert_eq!(fs::read(profile).unwrap(), live);
    }
    #[test]
    fn read_only_unix_inventory_classifies_external_live_and_changed_preserved_settings() {
        let f = Fixture::new();
        let location = location(&f);
        let Location::Unix { profile, .. } = &location else {
            unreachable!()
        };
        let mut retained = fs::OpenOptions::new().write(true).open(profile).unwrap();
        assert_eq!(
            f.run(Action::Install, location.clone(), vec![], &mut |_| Ok(()))
                .status,
            "complete"
        );
        use std::io::{Seek, SeekFrom, Write};
        retained.seek(SeekFrom::Start(0)).unwrap();
        retained.write_all(b"retained user change").unwrap();
        retained.sync_all().unwrap();
        let status = SqliteControlStore::open_current_read_only(&f.root)
            .unwrap()
            .status()
            .unwrap();
        let inventory = inspect_owned_artifacts(
            &f.root,
            RootIdentity::read(&f.root).unwrap(),
            &status.policy.installation_id,
            status.policy.policy_epoch,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(inventory.settings_conflicts);
        assert!(inventory.artifacts.iter().any(|artifact| artifact.class
            == PathArtifactClass::LiveUserSettings
            && !artifact.asg_owned_container));
        assert!(inventory.artifacts.iter().any(|artifact| artifact.class
            == PathArtifactClass::PreservedUserSettings
            && !artifact.matches_recorded_digest));
        assert_eq!(inventory.pending_operations, 0);
    }
}
