//! Synthetic native-manager receipts; no user services or login.
use super::*;
use crate::native_autostart::NativeKind;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, time::Duration};

struct Fixture {
    _temp: tempfile::TempDir,
    directory: PathBuf,
    store: NativeAutostartStore,
    registration: SupervisorRegistration,
}
impl Fixture {
    fn new(kind: NativeKind) -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let directory = root.join("synthetic native config");
        let location = match kind {
            NativeKind::LaunchAgent => NativeLocation::LaunchAgent {
                directory: directory.clone(),
                uid: 501,
            },
            _ => NativeLocation::SystemdUser {
                directory: directory.clone(),
            },
        };
        let supervisor = root.join("supervisor Unicode 空格 $ % & executable");
        fs::write(&supervisor, b"inert verified image, never executed").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&supervisor, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let registration = SupervisorRegistration {
            supervisor,
            supervisor_sha256: format!(
                "{:x}",
                Sha256::digest(b"inert verified image, never executed")
            ),
            catalog: root.join("synthetic catalog.db"),
        };
        fs::write(&registration.catalog, b"synthetic catalog").unwrap();
        let store = NativeAutostartStore::open(
            location,
            &directory.join("private-journal"),
            "synthetic-native-manager",
        )
        .unwrap();
        Self {
            _temp: temp,
            directory,
            store,
            registration,
        }
    }
    fn change(&self) -> AutostartChange {
        self.store.enable(&self.registration, None).unwrap()
    }
    fn target(&self) -> PathBuf {
        self.directory.join(self.store.entry_name())
    }
    fn properties(&self) -> Vec<u8> {
        [
            json!({"type":"s","data":self.store.entry_name()}),
            json!({"type":"s","data":self.target()}),
            json!({"type":"as","data":[]}),
            json!({"type":"s","data":"loaded"}),
            json!({"type":"s","data":"inactive"}),
            json!({"type":"s","data":"enabled"}),
            json!({"type":"b","data":false}),
        ]
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
    }
    fn command(&self) -> Vec<u8> {
        json!({"type":"a(sasbttttuii)","data":[[self.registration.supervisor,
            [self.registration.supervisor.to_str().unwrap(),"--db",self.registration.catalog.to_str().unwrap()],
            false,0,0,0,0,0,0,0]]}).to_string().into_bytes()
    }
    fn plist(&self) -> Vec<u8> {
        let xml = |s: &str| {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        };
        format!("<?xml version=\"1.0\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>Program</key><string>{}</string><key>ProgramArguments</key><array><string>{}</string><string>--db</string><string>{}</string></array><key>PID</key><integer>0</integer></dict></plist>",
            self.store.entry_name(),xml(self.registration.supervisor.to_str().unwrap()),xml(self.registration.supervisor.to_str().unwrap()),xml(self.registration.catalog.to_str().unwrap())).into_bytes()
    }
    fn response(&self, args: &[OsString]) -> LocalCapture {
        let stdout = if args.iter().any(|a| a == "LoadUnit") {
            json!({"type":"o","data":["/org/freedesktop/systemd1/unit/synthetic_2eservice"]})
                .to_string()
                .into_bytes()
        } else if args.iter().any(|a| a == "ExecStart") {
            self.command()
        } else if args.iter().any(|a| a == "NeedDaemonReload") {
            self.properties()
        } else {
            b"successful native warning allowed".to_vec()
        };
        LocalCapture {
            success: true,
            stdout,
            stderr: b"synthetic warning, never emitted".to_vec(),
        }
    }
}

#[test]
fn typed_systemd_readback_precedes_start_and_preserves_exact_argument_boundaries() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut calls = Vec::new();
    let state = apply_with(
        &f.store,
        &change,
        &f.registration,
        true,
        deadline,
        &mut |program, args, end| {
            assert_eq!(end, deadline);
            assert!(
                [
                    Path::new("/usr/bin/systemctl"),
                    Path::new("/bin/systemctl"),
                    Path::new("/usr/bin/busctl"),
                    Path::new("/bin/busctl"),
                ]
                .contains(&program)
            );
            calls.push(args.to_vec());
            Ok(f.response(args))
        },
    )
    .unwrap();
    assert!(
        state.manager_loaded && state.configured_command_verified && state.enabled == Some(true)
    );
    assert_eq!(state.manager_active, None);
    assert!(state.launch_requested);
    assert_eq!(calls.len(), 6);
    assert!(calls[1].iter().any(|a| a == "enable"));
    assert!(!calls[1].iter().any(|a| a == "--now"));
    assert!(calls[4].iter().any(|a| a == "ExecStart"));
    assert!(calls[5].iter().any(|a| a == "start"));
}

#[test]
fn stopped_desired_state_never_uses_enable_now_or_start() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let state = apply_with(
        &f.store,
        &change,
        &f.registration,
        false,
        Instant::now() + Duration::from_secs(2),
        &mut |_, args, _| {
            assert!(!args.iter().any(|a| a == "--now" || a == "start"));
            Ok(f.response(args))
        },
    )
    .unwrap();
    assert!(!state.launch_requested);
}

#[test]
fn failed_manager_stops_before_readback_or_start_and_preserves_configuration() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let before = fs::read(f.target()).unwrap();
    let mut count = 0;
    let error = apply_with(
        &f.store,
        &change,
        &f.registration,
        true,
        Instant::now() + Duration::from_secs(2),
        &mut |_, _, _| {
            count += 1;
            Ok(LocalCapture {
                success: false,
                stdout: b"synthetic-private-marker".to_vec(),
                stderr: b"private path".to_vec(),
            })
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Failed);
    assert_eq!(count, 1);
    assert_eq!(fs::read(f.target()).unwrap(), before);
    assert_eq!(f.store.latest_receipt().unwrap().unwrap(), change.receipt);
    assert!(!format!("{error:?} {error}").contains("synthetic-private-marker"));
}

#[test]
fn wrong_loaded_target_dropin_reload_or_command_refuses_start() {
    for failure in ["target", "dropin", "reload", "arguments", "extra-command"] {
        let f = Fixture::new(NativeKind::SystemdUser);
        let change = f.change();
        let error = apply_with(
            &f.store,
            &change,
            &f.registration,
            true,
            Instant::now() + Duration::from_secs(2),
            &mut |_, args, _| {
                assert!(!args.iter().any(|a| a == "start"));
                let mut output = f.response(args);
                if args.iter().any(|a| a == "NeedDaemonReload") {
                    let mut lines: Vec<Value> = std::str::from_utf8(&output.stdout)
                        .unwrap()
                        .lines()
                        .map(|s| serde_json::from_str(s).unwrap())
                        .collect();
                    match failure {
                        "target" => lines[1]["data"] = json!("/different.service"),
                        "dropin" => lines[2]["data"] = json!(["/override.conf"]),
                        "reload" => lines[6]["data"] = json!(true),
                        _ => {}
                    }
                    output.stdout = lines
                        .iter()
                        .map(Value::to_string)
                        .collect::<Vec<_>>()
                        .join("\n")
                        .into_bytes();
                }
                if args.iter().any(|a| a == "ExecStart") {
                    let mut v: Value = serde_json::from_slice(&output.stdout).unwrap();
                    if failure == "arguments" {
                        v["data"][0][1] = json!([
                            f.registration.supervisor.to_str().unwrap(),
                            format!("--db {}", f.registration.catalog.display())
                        ]);
                    }
                    if failure == "extra-command" {
                        let extra = v["data"][0].clone();
                        v["data"].as_array_mut().unwrap().push(extra);
                    }
                    output.stdout = v.to_string().into_bytes();
                }
                Ok(output)
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::VerificationFailed, "{failure}");
    }
}

#[test]
fn config_edit_or_binary_change_during_native_call_invalidates_receipt() {
    for binary in [false, true] {
        let f = Fixture::new(NativeKind::SystemdUser);
        let change = f.change();
        let error = apply_with(
            &f.store,
            &change,
            &f.registration,
            true,
            Instant::now() + Duration::from_secs(2),
            &mut |_, args, _| {
                let output = f.response(args);
                // Windows pins the executable without sharing-write permission;
                // Unix also tests a real write to the pinned image.
                if binary && cfg!(unix) {
                    fs::write(&f.registration.supervisor, b"different image").unwrap();
                } else {
                    fs::write(f.target(), b"independent setting change").unwrap();
                }
                Ok(output)
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
    }
}

#[test]
fn expired_operation_deadline_launches_no_native_command() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let error = apply_with(
        &f.store,
        &change,
        &f.registration,
        true,
        Instant::now(),
        &mut |_, _, _| panic!("expired operation spawned process"),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
}

#[test]
fn launchd_xml_identity_is_structural_and_rejects_entities_duplicates_and_wrong_args() {
    let f = Fixture::new(NativeKind::LaunchAgent);
    assert_eq!(
        launchd_readback(&f.plist(), f.store.entry_name(), &f.registration).unwrap(),
        Some(false)
    );
    let text = String::from_utf8(f.plist()).unwrap();
    for invalid in [
        text.replace("<string>--db</string>", "<string>--wrong</string>"),
        text.replace("</dict>", "<key>Label</key><string>other</string></dict>"),
        text.replace("<dict>", "<dict><key>Disabled</key><true/>"),
        text.replace(
            "<!DOCTYPE plist PUBLIC",
            "<!ENTITY forbidden \"other\"><!DOCTYPE plist PUBLIC",
        ),
        text.replace("<array>", "<array xmlns=\"other\">"),
    ] {
        assert_eq!(
            launchd_readback(invalid.as_bytes(), f.store.entry_name(), &f.registration)
                .unwrap_err()
                .code,
            ErrorCode::VerificationFailed
        );
    }
}

#[test]
fn loaded_launchd_is_checked_without_bootout_and_wrong_gui_context_is_refused() {
    for wrong_context in [false, true] {
        let f = Fixture::new(NativeKind::LaunchAgent);
        let change = f.change();
        let mut commands = Vec::new();
        let result = apply_with(
            &f.store,
            &change,
            &f.registration,
            true,
            Instant::now() + Duration::from_secs(2),
            &mut |_, args, _| {
                assert!(!args.iter().any(|a| a == "bootstrap" || a == "bootout"));
                commands.push(args.to_vec());
                let stdout = match args[0].to_str().unwrap() {
                    "manageruid" => b"501\n".to_vec(),
                    "managername" => {
                        if wrong_context {
                            b"Background\n".to_vec()
                        } else {
                            b"Aqua\n".to_vec()
                        }
                    }
                    "list" => f.plist(),
                    _ => b"private manager state".to_vec(),
                };
                Ok(LocalCapture {
                    success: true,
                    stdout,
                    stderr: vec![],
                })
            },
        );
        if wrong_context {
            assert_eq!(result.unwrap_err().code, ErrorCode::VerificationFailed);
        } else {
            assert!(result.unwrap().configured_command_verified);
            assert_eq!(commands.len(), 9);
            assert_eq!(commands[8][0], "kickstart");
            assert_eq!(commands[0][0], "manageruid");
            assert_eq!(commands[1][0], "managername");
            assert_eq!(commands[3][0], "list");
            assert_eq!(commands[7][0], "list");
        }
    }
}

#[test]
fn loaded_owned_predecessor_is_reloaded_but_unproven_job_is_preserved() {
    for proved in [true, false] {
        let mut f = Fixture::new(NativeKind::LaunchAgent);
        let previous = f.change();
        let old_plist = f.plist();
        let old_image = fs::read(&f.registration.supervisor).unwrap();
        f.registration.supervisor = f
            .registration
            .supervisor
            .with_file_name("new verified supervisor");
        fs::write(&f.registration.supervisor, old_image).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &f.registration.supervisor,
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let change = f
            .store
            .enable(&f.registration, Some(&previous.receipt))
            .unwrap();
        let mut reloaded = false;
        let mut mutation = Vec::new();
        let result = apply_with(
            &f.store,
            &change,
            &f.registration,
            true,
            Instant::now() + Duration::from_secs(2),
            &mut |_, args, _| {
                let action = args[0].to_str().unwrap();
                let stdout = match action {
                    "manageruid" => b"501\n".to_vec(),
                    "managername" => b"Aqua\n".to_vec(),
                    "list" if reloaded => f.plist(),
                    "list" if proved => old_plist.clone(),
                    "list" => String::from_utf8(old_plist.clone())
                        .unwrap()
                        .replace("synthetic catalog.db", "independent catalog.db")
                        .into_bytes(),
                    "bootstrap" => {
                        reloaded = true;
                        mutation.push(action.to_owned());
                        vec![]
                    }
                    "bootout" => {
                        mutation.push(action.to_owned());
                        vec![]
                    }
                    _ => vec![],
                };
                Ok(LocalCapture {
                    success: true,
                    stdout,
                    stderr: vec![],
                })
            },
        );
        if proved {
            let state = result.unwrap();
            assert!(state.configured_command_verified && state.launch_requested);
            assert_eq!(state.enabled, None);
            assert_eq!(mutation, ["bootout", "bootstrap"]);
        } else {
            assert_eq!(result.unwrap_err().code, ErrorCode::VerificationFailed);
            assert!(mutation.is_empty());
        }
    }
}

#[test]
fn missing_launchd_job_bootstraps_only_after_matching_gui_and_keeps_failure_receipt() {
    for mode in ["success", "wrong-context", "bootstrap-failed"] {
        let f = Fixture::new(NativeKind::LaunchAgent);
        let change = f.change();
        let mut loaded = false;
        let mut bootstraps = 0;
        let result = apply_with(
            &f.store,
            &change,
            &f.registration,
            true,
            Instant::now() + Duration::from_secs(2),
            &mut |_, args, _| {
                let action = args[0].to_str().unwrap();
                let mut success = true;
                let stdout = match action {
                    "manageruid" => b"501\n".to_vec(),
                    "managername" => {
                        if mode == "wrong-context" {
                            b"Background\n".to_vec()
                        } else {
                            b"Aqua\n".to_vec()
                        }
                    }
                    "print" if !loaded => {
                        success = false;
                        vec![]
                    }
                    "bootstrap" => {
                        bootstraps += 1;
                        loaded = true;
                        success = mode != "bootstrap-failed";
                        vec![]
                    }
                    "list" => f.plist(),
                    _ => vec![],
                };
                Ok(LocalCapture {
                    success,
                    stdout,
                    stderr: vec![],
                })
            },
        );
        match mode {
            "success" => {
                assert!(result.unwrap().launch_requested);
                assert_eq!(bootstraps, 1);
            }
            "wrong-context" => {
                assert_eq!(result.unwrap_err().code, ErrorCode::VerificationFailed);
                assert_eq!(bootstraps, 0);
            }
            _ => {
                assert_eq!(result.unwrap_err().code, ErrorCode::Failed);
                assert_eq!(bootstraps, 1);
            }
        }
        assert_eq!(f.store.latest_receipt().unwrap().unwrap(), change.receipt);
    }
}

#[test]
fn manager_start_failure_retains_verified_loaded_state() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let error = apply_with(
        &f.store,
        &change,
        &f.registration,
        true,
        Instant::now() + Duration::from_secs(2),
        &mut |_, args, _| {
            let mut output = f.response(args);
            if args.iter().any(|a| a == "start") {
                output.success = false;
            }
            Ok(output)
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Failed);
    let observed = error.observed.unwrap();
    assert!(
        observed.manager_loaded
            && observed.configured_command_verified
            && observed.launch_requested
    );
    assert_eq!(observed.manager_active, None);
    assert_eq!(observed.enabled, Some(true));
}

#[test]
fn identical_unowned_configuration_is_only_inspected_and_never_activated() {
    let f = Fixture::new(NativeKind::SystemdUser);
    f.store.preexisting_registration_for_test(&f.registration);
    let change = f.change();
    assert!(!change.receipt.owned);
    let state = apply_with(
        &f.store,
        &change,
        &f.registration,
        true,
        Instant::now() + Duration::from_secs(2),
        &mut |_, args, _| {
            assert!(
                !args
                    .iter()
                    .any(|a| a == "enable" || a == "start" || a == "daemon-reload")
            );
            Ok(f.response(args))
        },
    )
    .unwrap();
    assert!(state.configured_command_verified);
    assert!(!state.launch_requested);
    assert!(!f.store.latest_receipt().unwrap().unwrap().owned);
}

#[test]
fn busy_native_owner_is_distinct_from_configuration_change() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let guard = f
        .store
        .manager_registration(&change.receipt, &f.registration)
        .unwrap();
    let error = apply_with(
        &f.store,
        &change,
        &f.registration,
        true,
        Instant::now() + Duration::from_secs(2),
        &mut |_, _, _| panic!("busy owner executed command"),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Busy);
    drop(guard);
}

#[cfg(windows)]
#[test]
fn windows_run_registration_has_no_manager_loaded_or_live_identity_claim() {
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW,
        RegDeleteTreeW,
    };
    struct TestKey(String);
    impl Drop for TestKey {
        fn drop(&mut self) {
            assert!(
                self.0
                    .starts_with(r"Software\AgentSessionGrepNativeManagerTests\")
            );
            let name: Vec<_> = self.0.encode_utf16().chain(Some(0)).collect();
            assert_eq!(
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, name.as_ptr()) },
                0
            );
        }
    }
    let mut f = Fixture::new(NativeKind::SystemdUser);
    // Keep the fixture Run command within Windows' documented 260-unit limit.
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).unwrap();
    let name = format!(
        r"Software\AgentSessionGrepNativeManagerTests\{}-{:x}",
        std::process::id(),
        u64::from_le_bytes(nonce)
    );
    let key = TestKey(name);
    let wide: Vec<_> = key.0.encode_utf16().chain(Some(0)).collect();
    let mut handle = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut handle,
                std::ptr::null_mut(),
            )
        },
        0
    );
    unsafe { RegCloseKey(handle) };
    f.registration.supervisor = f.registration.supervisor.with_file_name("supervisor.exe");
    fs::write(
        &f.registration.supervisor,
        b"inert verified image, never executed",
    )
    .unwrap();
    f.registration.catalog = f.registration.catalog.with_file_name("cat.db");
    fs::write(&f.registration.catalog, b"synthetic catalog").unwrap();
    f.store = NativeAutostartStore::open(
        NativeLocation::WindowsRun {
            subkey: key.0.clone(),
        },
        &f.directory.join("private-journal"),
        "native-run-fixture",
    )
    .unwrap();
    let change = f.change();
    let state = apply_with(
        &f.store,
        &change,
        &f.registration,
        false,
        Instant::now() + Duration::from_secs(2),
        &mut |_, _, _| panic!("Run registration invoked a manager"),
    )
    .unwrap();
    assert!(state.registration_present && state.configured_command_verified);
    assert!(!state.manager_loaded);
    assert_eq!(state.manager_active, None);
    assert!(!state.launch_requested);
}

#[test]
fn start_spawn_failure_retains_readback_without_claiming_a_native_request() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let error = apply_with(
        &f.store,
        &change,
        &f.registration,
        true,
        Instant::now() + Duration::from_secs(2),
        &mut |_, args, _| {
            if args.iter().any(|a| a == "start") {
                return Err(ErrorCode::Unavailable.into());
            }
            Ok(f.response(args))
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    let observed = error.observed.unwrap();
    assert!(observed.manager_loaded && observed.configured_command_verified);
    assert!(!observed.launch_requested);
    assert_eq!(observed.manager_active, None);
}

#[test]
fn owned_reload_and_latest_start_gate_do_not_launch_under_maintenance_or_disable() {
    for late_disable in [false, true] {
        let f = Fixture::new(NativeKind::SystemdUser);
        let change = f.change();
        let mut calls = Vec::new();
        let mut checks = 0;
        let end = Instant::now() + Duration::from_secs(2);
        let state = apply_checked(
            &f.store,
            &change,
            &f.registration,
            StartPolicy {
                run_now: true,
                no_start: false,
                reconcile: true,
            },
            end,
            &mut || {
                checks += 1;
                Ok(!late_disable)
            },
            &mut |_, args, deadline| {
                assert_eq!(deadline, end);
                calls.push(args.to_vec());
                Ok(f.response(args))
            },
        )
        .unwrap();
        assert_eq!(checks, 1);
        assert_eq!(state.launch_requested, !late_disable);
        assert_eq!(
            calls
                .iter()
                .any(|args| args.iter().any(|arg| arg == "start")),
            !late_disable
        );
        let state = apply_checked(
            &f.store,
            &change,
            &f.registration,
            StartPolicy {
                run_now: false,
                no_start: true,
                reconcile: true,
            },
            end,
            &mut || panic!("reload should never ask to start"),
            &mut |_, args, _| {
                assert!(!args.iter().any(|arg| arg == "start"));
                Ok(f.response(args))
            },
        )
        .unwrap();
        assert!(!state.launch_requested && state.configured_command_verified);
    }
}

#[test]
fn fenced_launchd_reload_defers_runatload_bootstrap_and_never_kickstarts() {
    let f = Fixture::new(NativeKind::LaunchAgent);
    let change = f.change();
    let mut calls = Vec::new();
    let state = apply_checked(
        &f.store,
        &change,
        &f.registration,
        StartPolicy {
            run_now: false,
            no_start: true,
            reconcile: true,
        },
        Instant::now() + Duration::from_secs(2),
        &mut || Ok(false),
        &mut |_, args, _| {
            calls.push(args.to_vec());
            assert!(
                !args
                    .iter()
                    .any(|arg| arg == "bootstrap" || arg == "kickstart")
            );
            let stdout = match args[0].to_str().unwrap() {
                "manageruid" => b"501\n".to_vec(),
                "managername" => b"Aqua\n".to_vec(),
                _ => vec![],
            };
            Ok(LocalCapture {
                success: args[0] != "print",
                stdout,
                stderr: vec![],
            })
        },
    )
    .unwrap();
    assert!(!state.manager_loaded && !state.launch_requested);
    assert_eq!(calls.len(), 3);
}

#[test]
fn owned_restart_with_latest_false_does_not_enable_load_or_spawn() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let state = restart_owned_for_update(
        &f.store,
        &change,
        &f.registration,
        Instant::now() + Duration::from_secs(1),
        &mut || Ok(false),
    )
    .unwrap();
    assert!(!state.launch_requested && !state.manager_loaded);
    assert_eq!(f.store.latest_receipt().unwrap().unwrap(), change.receipt);
}

#[test]
fn supervisor_drain_returns_held_os_guard_and_uses_original_deadline() {
    use agent_session_grep_adapters_sqlite::managed_locks::{
        ExclusiveGuard, LockKind, RootIdentity,
    };
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let identity = RootIdentity::read(&root).unwrap();
    let held =
        crate::retry_fixture_busy(|| ExclusiveGuard::try_acquire(&root, LockKind::Supervisor));
    let start = Instant::now();
    let result = wait_supervisor_drained(&root, identity, start + Duration::from_millis(40));
    assert_eq!(result.unwrap_err().code, ErrorCode::Timeout);
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(held);
    let proof =
        wait_supervisor_drained(&root, identity, Instant::now() + Duration::from_secs(1)).unwrap();
    assert!(ExclusiveGuard::try_acquire(&root, LockKind::Supervisor).is_err());
    drop(proof);
    assert!(ExclusiveGuard::try_acquire(&root, LockKind::Supervisor).is_ok());
}

#[cfg(windows)]
#[test]
fn detached_supervisor_survives_parent_job_cleanup_and_does_not_hold_capture_pipes() {
    use std::process::Command;
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    // Execute the unchanged production boundary in a synthetic subprocess. Its
    // jobs never attach to the parallel Cargo test process or any native job.
    let module =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/native_manager.rs"))
            .unwrap();
    let begin = module.find("mod detached {").unwrap();
    let tail = module[begin..].find("\nfn native_error(").unwrap();
    let boundary = &module[begin..begin + tail];
    let prefix = r#"
use std::{ffi::{OsStr, OsString}, path::{Path, PathBuf}, time::Instant};
struct SupervisorRegistration { supervisor:PathBuf, catalog:PathBuf }
#[derive(Debug)] enum ErrorCode { Unavailable, Failed, VerificationFailed, Timeout }
#[derive(Debug)] struct ManagerError(ErrorCode);
impl From<ErrorCode> for ManagerError { fn from(code:ErrorCode)->Self { Self(code) } }
type Result<T> = std::result::Result<T,ManagerError>;
"#;
    let main = r#"
use std::time::Duration;
use windows_sys::Win32::{Foundation::{CloseHandle, HANDLE}, System::{JobObjects::*, Threading::{GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION}}};
fn create_job(flags:u32)->HANDLE {
 let job=unsafe{CreateJobObjectW(std::ptr::null(),std::ptr::null())};
 assert!(!job.is_null());
 let limits=JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
   BasicLimitInformation:JOBOBJECT_BASIC_LIMIT_INFORMATION {LimitFlags:flags,..Default::default()},
   ..Default::default()
 };
 assert_ne!(unsafe{SetInformationJobObject(job,JobObjectExtendedLimitInformation,(&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),std::mem::size_of_val(&limits) as u32)},0);
 assert_ne!(unsafe{AssignProcessToJobObject(job,GetCurrentProcess())},0);
 job
}
fn main() {
 let args:Vec<_>=std::env::args_os().skip(1).collect();
 if args.first().is_some_and(|arg|arg=="--db") {
   let marker=Path::new(&args[1]);
   // Stay alive across the parent's cleanup. Report only the synthetic PID.
   std::fs::write(marker.with_extension("pid"),std::process::id().to_string()).unwrap();
   std::thread::sleep(Duration::from_millis(1200));
   std::fs::write(marker,b"detached survived").unwrap();
   return;
 }
 // This controlled ancestor prohibits breakaway but has no kill-on-close.
 // A child may remain there without inheriting the updater's cleanup lifetime.
 let ancestor=create_job(0);
 let blocked=args.get(1).is_some_and(|arg|arg=="blocked");
 let job=create_job(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | if blocked {0} else {JOB_OBJECT_LIMIT_BREAKAWAY_OK});
 let exe=std::env::current_exe().unwrap();
 let f=std::fs::File::open(&exe).unwrap();
 let marker=PathBuf::from(&args[0]);
 let result=detached::spawn(&SupervisorRegistration{supervisor:exe,catalog:marker.clone()},f,Instant::now()+Duration::from_secs(2));
 if blocked {
   assert!(matches!(result,Err(ManagerError(ErrorCode::Unavailable))));
   assert!(!marker.with_extension("pid").exists());
   assert!(!marker.exists());
   return;
 }
 result.unwrap();
 let end=Instant::now()+Duration::from_millis(700);
 let pid_path=marker.with_extension("pid");
 while !pid_path.exists() && Instant::now()<end {std::thread::sleep(Duration::from_millis(5));}
 let pid:u32=std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
 let child=unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid)};
 assert!(!child.is_null());
 let mut member=0;
 assert_ne!(unsafe{IsProcessInJob(child,job,&mut member)},0);
 assert_eq!(member,0,"child inherited the parent's specific kill job");
 assert_ne!(unsafe{IsProcessInJob(child,ancestor,&mut member)},0);
 assert_ne!(member,0,"fixture must exercise a retained non-breakaway ancestor");
 assert_ne!(unsafe{CloseHandle(child)},0);
 // Process exit closes the final own-job handle. Detached child must survive.
}
"#;
    // Use the currently built windows-sys library, not another Cargo build.
    let exe = root.join("detached-fixture.exe");
    let source = root.join("detached-fixture.rs");
    fs::write(&source, format!("{prefix}\n{boundary}\n{main}")).unwrap();
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    // Bind to the exact dependency fingerprint of THIS executable. Cargo may
    // retain rlibs with other feature sets or newer check/build timestamps;
    // neither directory order nor modification time proves API availability.
    let executable = std::env::current_exe().unwrap();
    let executable_key = executable
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .replace("agent_session_grep_cli-", "agent-session-grep-cli-");
    let fingerprint_root = deps.parent().unwrap().join(".fingerprint");
    let current: serde_json::Value = serde_json::from_slice(
        &fs::read(
            fingerprint_root
                .join(executable_key)
                .join("test-lib-agent_session_grep_cli.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let dependency = current["deps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry.get(1).and_then(serde_json::Value::as_str) == Some("windows_sys"))
        .collect::<Vec<_>>();
    assert_eq!(
        dependency.len(),
        1,
        "current test dependency must identify one windows-sys artifact"
    );
    let dependency_hash = dependency[0][3].as_u64().unwrap();
    let expected_fingerprint: String = dependency_hash
        .to_le_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&fingerprint_root).unwrap() {
        let directory = entry.unwrap().path();
        let Some(key) = directory.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !key.starts_with("windows-sys-") {
            continue;
        }
        let metadata = directory.join("lib-windows_sys.json");
        let stamp = directory.join("lib-windows_sys");
        if !metadata.is_file()
            || !stamp.is_file()
            || fs::read_to_string(stamp).unwrap().trim() != expected_fingerprint
        {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(metadata).unwrap()).unwrap();
        let features: Vec<String> =
            serde_json::from_str(value["features"].as_str().unwrap()).unwrap();
        for required in [
            "Win32_Foundation",
            "Win32_Security",
            "Win32_System_Threading",
            "Win32_System_JobObjects",
        ] {
            assert!(
                features.iter().any(|feature| feature == required),
                "current windows-sys dependency lacks required fixture feature {required}"
            );
        }
        let key = key.strip_prefix("windows-sys-").unwrap();
        let artifact = deps.join(format!("libwindows_sys-{key}.rlib"));
        assert!(
            artifact.is_file(),
            "fingerprinted windows-sys rlib must exist"
        );
        candidates.push(artifact);
    }
    assert_eq!(
        candidates.len(),
        1,
        "current fingerprint must select exactly one feature-correct windows-sys rlib"
    );
    let windows = candidates.pop().unwrap();
    let output = Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("--extern")
        .arg(format!("windows_sys={}", windows.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "synthetic native process fixture failed compilation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let marker = root.join("survived");
    let started = Instant::now();
    let output = Command::new(&exe).arg(&marker).output().unwrap();
    assert!(
        output.status.success(),
        "synthetic detached parent failed: exit={:?}, diagnostic={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !marker.exists(),
        "detached child inherited parent output pipes"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    let end = Instant::now() + Duration::from_secs(2);
    while !marker.exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read(&marker).unwrap(), b"detached survived");
    let blocked = root.join("blocked");
    let output = Command::new(&exe)
        .arg(&blocked)
        .arg("blocked")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "non-breakaway job must refuse detached spawn: exit={:?}, diagnostic={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!blocked.exists());
    assert!(!blocked.with_extension("pid").exists());
}

#[test]
fn owned_systemd_disable_checks_command_before_stop_and_readback_before_removal() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    let sibling = f.directory.join("unrelated.service");
    fs::write(&sibling, b"unrelated native settings").unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    let mut enabled = true;
    let mut calls = Vec::new();
    let mut checks = 0;
    let disabled = disable_owned(
        &f.store,
        &change.receipt,
        &f.registration,
        end,
        &mut || {
            checks += 1;
            Ok(())
        },
        &mut |_, args, deadline| {
            assert_eq!(deadline, end);
            calls.push(args.to_vec());
            if args.iter().any(|a| a == "disable") {
                enabled = false;
            }
            let mut response = f.response(args);
            if !enabled && args.iter().any(|a| a == "NeedDaemonReload") {
                response.stdout = String::from_utf8(response.stdout)
                    .unwrap()
                    .replace("\"enabled\"", "\"disabled\"")
                    .into_bytes();
            }
            Ok(response)
        },
    )
    .unwrap();
    assert_eq!(disabled.change.receipt.state, ConfigurationState::Absent);
    assert!(!disabled.summary.registration_present);
    assert!(disabled.summary.stop_requested);
    assert_eq!(disabled.summary.manager_active, Some(false));
    assert_eq!(disabled.summary.manager_loaded, None);
    assert!(!disabled.summary.unload_requested);
    assert!(!f.target().exists());
    assert_eq!(fs::read(sibling).unwrap(), b"unrelated native settings");
    let stop = calls
        .iter()
        .position(|args| args.iter().any(|a| a == "stop"))
        .unwrap();
    assert!(
        calls[..stop]
            .iter()
            .any(|args| args.iter().any(|a| a == "ExecStart"))
    );
    assert!(
        calls
            .iter()
            .any(|args| args.iter().any(|a| a == "--no-reload"))
    );
    assert!(checks > calls.len());
    assert_eq!(
        f.store.latest_receipt().unwrap(),
        Some(disabled.change.receipt)
    );
}

#[test]
fn owned_disable_rejects_loaded_command_mismatch_and_postprobe_preflight_failure() {
    for mismatch in [true, false] {
        let f = Fixture::new(NativeKind::SystemdUser);
        let change = f.change();
        let observed = std::cell::Cell::new(false);
        let mut mutations = 0;
        let result = disable_owned(
            &f.store,
            &change.receipt,
            &f.registration,
            Instant::now() + Duration::from_secs(2),
            &mut || {
                if !mismatch && observed.get() {
                    Err(ErrorCode::Conflict.into())
                } else {
                    Ok(())
                }
            },
            &mut |_, args, _| {
                if args
                    .iter()
                    .any(|a| a == "stop" || a == "disable" || a == "daemon-reload")
                {
                    mutations += 1;
                }
                let mut response = f.response(args);
                if args.iter().any(|a| a == "ExecStart") {
                    observed.set(true);
                    if mismatch {
                        response.stdout=json!({"type":"a(sasbttttuii)","data":[["/synthetic/unowned",["/synthetic/unowned"],false,0,0,0,0,0,0,0]]}).to_string().into_bytes();
                    }
                }
                Ok(response)
            },
        );
        assert!(result.is_err());
        assert_eq!(mutations, 0);
        assert!(f.target().exists());
        assert_eq!(f.store.latest_receipt().unwrap(), Some(change.receipt));
    }
}

#[test]
fn owned_launchd_disable_verifies_current_job_and_whole_domain_absence() {
    let f = Fixture::new(NativeKind::LaunchAgent);
    let change = f.change();
    let mut mutations = Vec::new();
    let disabled = disable_owned(
        &f.store,
        &change.receipt,
        &f.registration,
        Instant::now() + Duration::from_secs(2),
        &mut || Ok(()),
        &mut |_, args, _| {
            let action = args[0].to_str().unwrap();
            let stdout = match action {
                "manageruid" => b"501\n".to_vec(),
                "managername" => b"Aqua\n".to_vec(),
                "list" if args.len() > 1 => f.plist(),
                "list" => b"PID\tStatus\tLabel\n-\t0\tunrelated.synthetic.job\n".to_vec(),
                "bootout" => {
                    mutations.push(action.to_owned());
                    vec![]
                }
                _ => vec![],
            };
            Ok(LocalCapture {
                success: true,
                stdout,
                stderr: vec![],
            })
        },
    )
    .unwrap();
    assert_eq!(mutations, ["bootout"]);
    assert!(disabled.summary.unload_requested && disabled.summary.stop_requested);
    assert_eq!(disabled.summary.manager_loaded, Some(false));
    assert!(!f.target().exists());
    assert!(launchd_absent(b"PID\tStatus\tLabel\n", f.store.entry_name()).is_ok());
    assert!(launchd_absent(b"arbitrary failed diagnostics", f.store.entry_name()).is_err());
    let present = format!("PID\tStatus\tLabel\n-\t0\t{}\n", f.store.entry_name());
    assert!(launchd_absent(present.as_bytes(), f.store.entry_name()).is_err());
}

#[test]
fn disable_preserves_user_edit_unowned_receipt_and_expired_deadline() {
    let f = Fixture::new(NativeKind::SystemdUser);
    let change = f.change();
    fs::write(f.target(), b"independently edited owned key").unwrap();
    let result = disable_owned(
        &f.store,
        &change.receipt,
        &f.registration,
        Instant::now() + Duration::from_secs(2),
        &mut || Ok(()),
        &mut |_, _, _| panic!("edited config must not run a manager"),
    );
    assert_eq!(result.err().unwrap().code, ErrorCode::Conflict);
    assert_eq!(
        fs::read(f.target()).unwrap(),
        b"independently edited owned key"
    );
    let result = disable_owned(
        &f.store,
        &change.receipt,
        &f.registration,
        Instant::now(),
        &mut || panic!("expired operation must do no preflight I/O"),
        &mut |_, _, _| panic!(),
    );
    assert_eq!(result.err().unwrap().code, ErrorCode::Timeout);
}
