//! Actual CLI output for a retained restart failure; no native startup or package apply.
use agent_session_grep_adapters_sqlite::managed_locks::RootIdentity;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
const HISTORICAL_WARNING: &str = "Recorded restart failure (reason=unknown; no restart attempted by this invocation). Preserve state and inspect update status before recovery.";

#[cfg(not(windows))]
fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[cfg(windows)]
fn private_directory(path: &Path) {
    use std::{
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::CreateDirectoryW,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct Local(*mut std::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: each allocation below is returned by a LocalAlloc-based API.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let mut token = ptr::null_mut();
    // SAFETY: valid output pointer, then one OwnedHandle owns the returned token.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    // SAFETY: this first call queries the required buffer length only.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut size,
        );
    }
    assert!(size as usize >= std::mem::size_of::<TOKEN_USER>());
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the sized, aligned buffer remains alive while its SID is used.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        },
        0
    );
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = ptr::null_mut();
    // SAFETY: the SID comes from the successful TokenUser query.
    assert_ne!(
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) },
        0
    );
    let _sid_allocation = Local(sid.cast());
    let mut len = 0;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 allocation.
    unsafe {
        while *sid.add(len) != 0 {
            len += 1;
        }
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(sid, len) }).unwrap();
    // Same protected, current-user-only descriptor as the real journal creator;
    // ordinary inherited temp-directory ACLs are intentionally not admitted.
    let sddl: Vec<u16> = format!("O:{value}D:P(A;OICI;FA;;;{value})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: NUL-terminated SDDL and a valid output pointer.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0
    );
    let descriptor = Local(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers remain alive for CreateDirectoryW; the path is fresh.
    assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(), &attributes) }, 0);
}

fn status_fixture(prefix: &Path, phase: &str, failed: bool) -> (PathBuf, Vec<u8>) {
    let update = prefix.join("update");
    private_directory(&update);
    private_directory(&update.join("wire_restart_warning"));
    let catalog = prefix.join("PRIVATE_CATALOG_SENTINEL.db");
    let identity = json!({
        "version":"0.2.0-beta.1",
        "target":agent_session_grep_launcher::metadata::BUILD_TARGET,
        "source_commit":"a".repeat(40),
        "relative_dir":format!("versions/0.2.0-beta.1-{}", "b".repeat(12)),
        "app_sha256":"b".repeat(64),
        "catalog_schema":agent_session_grep_adapters_sqlite::SCHEMA_VERSION,
        "control_schema":agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION,
        "launcher_protocol":1,
    });
    let state = json!({
        "schema":"asg.update-state/v1", "update_id":"wire_restart_warning",
        "owner_nonce":"wire_owner", "seq":1,
        "prefix_binding":RootIdentity::read(prefix).unwrap().control_id().as_str(),
        "phase":phase, "old":identity, "new":identity,
        "archive_sha256":"c".repeat(64), "manifest_sha256":"d".repeat(64),
        "old_pointer_generation":1, "new_pointer_generation":2,
        "stable_launcher_sha256":"e".repeat(64), "resumed":false,
        "recovery_incarnation":null, "catalog":catalog,
        "checkpoint":{"installation_id":"wire_installation", "policy_epoch":0,
            "control_seq":0, "desired_updates":"paused", "catalog_incarnation":"wire_catalog",
            "catalog_generation":0, "catalog_schema":agent_session_grep_adapters_sqlite::SCHEMA_VERSION},
        "quiesced_checkpoint":null, "native_binding_sha256":null, "backup":null,
        "staged":false, "migrated":false, "self_checked":false,
        "pending":null, "effects":[], "cleanup_pending":false,
        "error_code":if failed { Some("restart_failed") } else { None },
    });
    let bytes = serde_json::to_vec(&state).unwrap();
    let file = update.join("state.json");
    fs::write(&file, &bytes).unwrap();
    (file, bytes)
}

#[test]
fn recorded_restart_warning_reaches_actual_status_and_apply_wire() {
    for (phase, failed, expected_exit) in [
        ("verified", true, 10),
        ("rolled_back", true, 0),
        ("verified", false, 10),
    ] {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        let (state_path, before) = status_fixture(&prefix, phase, failed);
        for mode in ["json", "jsonl", "human"] {
            for action in if phase == "verified" {
                vec!["status", "apply"]
            } else {
                vec!["status"]
            } {
                let mut command = Command::new(BIN);
                command
                    .arg("--output")
                    .arg(mode)
                    .args(["update", action, "--install-prefix"])
                    .arg(&prefix);
                if action == "apply" {
                    // The retained unfinished journal must win before this absent
                    // archive is opened, and must never replay an installation.
                    command.arg("--from").arg(prefix.join("absent.zip"));
                }
                let result = command.output().unwrap();
                assert_eq!(
                    result.status.code(),
                    Some(expected_exit),
                    "{phase}/{mode}/{action}: stderr={}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let stdout = String::from_utf8(result.stdout).unwrap();
                let stderr = String::from_utf8(result.stderr).unwrap();
                if mode == "human" {
                    let expected = if failed {
                        format!("warning: {HISTORICAL_WARNING}\n")
                    } else {
                        String::new()
                    };
                    assert_eq!(stderr.replace("\r\n", "\n"), expected);
                    assert!(!stdout.contains(HISTORICAL_WARNING));
                } else {
                    assert!(stderr.is_empty());
                    assert_eq!(stdout.lines().count(), 1);
                    let frame: Value = serde_json::from_str(&stdout).unwrap();
                    assert_eq!(frame["command"], format!("update.{action}"));
                    assert_eq!(
                        frame["outcome"],
                        if expected_exit == 0 {
                            "success"
                        } else {
                            "partial"
                        }
                    );
                    assert_eq!(
                        frame["warnings"],
                        if failed {
                            json!([HISTORICAL_WARNING])
                        } else {
                            json!([])
                        }
                    );
                    assert_eq!(frame["data"]["freshness"], "unknown");
                    assert!(frame["data"].get("resumed").is_none());
                }
                assert!(!stdout.contains("PRIVATE_CATALOG_SENTINEL"));
                assert!(!stderr.contains("PRIVATE_CATALOG_SENTINEL"));
                assert_eq!(fs::read(&state_path).unwrap(), before);
                assert!(!prefix.join("current.json").exists());
                assert!(!prefix.join("PRIVATE_CATALOG_SENTINEL.db").exists());
                assert_eq!(fs::read_dir(prefix.join("update")).unwrap().count(), 2);
            }
        }
    }
}
