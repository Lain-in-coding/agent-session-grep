use std::{
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
};

use agent_session_grep_launcher::{
    LauncherError,
    metadata::{APP_NAME, BUILD_TARGET},
    verify_installation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn probe() -> &'static Path {
    static PROBE: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    &PROBE
        .get_or_init(|| {
            let temp = tempfile::tempdir().unwrap();
            let binary = temp.path().join(APP_NAME);
            let result = Command::new("rustc")
                .arg("--edition=2024")
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/child.rs"))
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "probe build: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            (temp, binary)
        })
        .1
}

struct Fixture {
    // Forking while another test writes an executable can inherit that writer
    // until exec, causing ETXTBSY even after the creating thread closes it.
    // Serialize the synthetic write/execute lifetime, not production launching.
    #[cfg(unix)]
    _process_guard: std::sync::MutexGuard<'static, ()>,
    _temp: TempDir,
    prefix: PathBuf,
    launcher: PathBuf,
    app: PathBuf,
    pointer: Value,
    release: Value,
}

impl Fixture {
    fn new() -> Self {
        #[cfg(unix)]
        static PROCESS_FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        #[cfg(unix)]
        let process_guard = PROCESS_FIXTURE.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        // macOS's temporary root can itself be an alias. Positive fixtures use
        // the real root; negative link tests explicitly create their own links.
        let prefix = temp
            .path()
            .canonicalize()
            .unwrap()
            .join("package with spaces");
        fs::create_dir(&prefix).unwrap();
        let bytes = fs::read(probe()).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let version = "0.2.0-beta.1";
        let dir = format!("versions/{version}-{}", &digest[..12]);
        fs::create_dir_all(prefix.join(&dir)).unwrap();
        let app = prefix.join(&dir).join(APP_NAME);
        fs::copy(probe(), &app).unwrap();
        let launcher = prefix.join(APP_NAME);
        fs::copy(env!("CARGO_BIN_EXE_agent-session-grep-launcher"), &launcher).unwrap();
        let pointer = json!({"schema":"asg.current/v1", "generation":7, "version":version,
            "dir":dir, "app":APP_NAME, "app_sha256":digest, "launcher_protocol":1,
            "activated_at":"2026-10-17T00:00:00Z"});
        let release = json!({"schema":"asg.version/v1", "version":version, "target":BUILD_TARGET,
            "source_commit":"0123456789abcdef0123456789abcdef01234567", "app_sha256":digest,
            "catalog_schema":19, "control_schema":1, "launcher_protocol_min":1,
            "launcher_protocol_max":1, "built_at":"2026-10-17T00:00:00Z"});
        let fixture = Self {
            #[cfg(unix)]
            _process_guard: process_guard,
            _temp: temp,
            prefix,
            launcher,
            app,
            pointer,
            release,
        };
        fixture.save();
        fixture
    }

    fn save(&self) {
        fs::write(
            self.prefix.join("current.json"),
            serde_json::to_vec(&self.pointer).unwrap(),
        )
        .unwrap();
        fs::write(
            self.app.parent().unwrap().join("release.json"),
            serde_json::to_vec(&self.release).unwrap(),
        )
        .unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(&self.launcher)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn error(&self, expected: LauncherError) {
        let output = self.run(&["--asg-launcher-info"]);
        assert_eq!(output.status.code(), Some(expected.exit_code()));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("{expected}\n")
        );
    }
}

#[test]
fn valid_installation_reports_only_verified_content_free_identity_and_alias_matches() {
    let fixture = Fixture::new();
    let verified = verify_installation(&fixture.prefix).unwrap();
    assert_eq!(verified.info().generation, 7);
    let output = fixture.run(&["--asg-launcher-info"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let info: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        info,
        json!({"schema":"asg.launcher-info/v1", "launcher_protocol":1,
        "target":BUILD_TARGET, "generation":7, "version":"0.2.0-beta.1",
        "source_commit":"0123456789abcdef0123456789abcdef01234567",
        "app_sha256":fixture.pointer["app_sha256"], "catalog_schema":19, "control_schema":1})
    );
    let alias = fixture
        .prefix
        .join(if cfg!(windows) { "asg.exe" } else { "asg" });
    fs::copy(&fixture.launcher, &alias).unwrap();
    let alias_output = Command::new(alias)
        .arg("--asg-launcher-info")
        .output()
        .unwrap();
    assert_eq!(alias_output.stdout, output.stdout);
    assert!(alias_output.status.success());
}

#[test]
fn verified_background_child_preserves_exit_status_without_terminal_inheritance() {
    let fixture = Fixture::new();
    for code in [0_u32, 37_u32, 0xffff_fff0] {
        #[cfg(unix)]
        if code > 255 {
            continue;
        }
        let app = verify_installation(&fixture.prefix).unwrap();
        let mut child = app
            .spawn_background(&["exit".into(), code.to_string().into()])
            .unwrap();
        assert_ne!(child.id(), 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert_eq!(status, code as i32);
        assert_eq!(child.try_wait().unwrap(), Some(status));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn background_exec_uses_verified_descriptor_after_executable_name_replacement() {
    let fixture = Fixture::new();
    let app = verify_installation(&fixture.prefix).unwrap();
    fs::rename(&fixture.app, fixture.app.with_extension("retired")).unwrap();
    fs::write(&fixture.app, b"invalid replacement executable").unwrap();
    let marker = fixture.prefix.join("background-marker");
    let mut child = app
        .spawn_background(&["write-marker".into(), marker.clone().into_os_string()])
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status, 0);
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(fs::read(marker).unwrap(), b"started");
}

#[test]
fn invalid_pointer_fields_and_containment_fail_closed() {
    let mut fixture = Fixture::new();
    let baseline = fixture.pointer.clone();
    let invalid = [
        ("schema", json!("asg.current/v2")),
        ("generation", json!(0)),
        ("generation", json!(-1)),
        ("generation", json!("7")),
        ("dir", json!("../outside-private-marker")),
        ("dir", json!("/outside-private-marker")),
        ("dir", json!("C:\\outside-private-marker")),
        ("dir", json!("versions/../outside")),
        ("dir", json!("versions\\same")),
        ("dir", json!("versions/extra/file")),
        ("dir", json!("versions/0.2.0-beta.1-000000000000")),
        ("app", json!("../outside-private-marker")),
        ("app", json!("script.cmd")),
        ("version", json!("01.2.0")),
        ("version", json!("0.2.0/evil")),
        ("app_sha256", json!("A".repeat(64))),
        ("activated_at", json!("2026-02-30T00:00:00Z")),
        ("activated_at", json!("2026-10-17T00:00:00+01:00")),
        ("activated_at", json!("2026-10-17T00:00:00-00:00")),
        ("unexpected", json!("outside-private-marker")),
    ];
    for (key, value) in invalid {
        fixture.pointer = baseline.clone();
        fixture.pointer[key] = value;
        fixture.save();
        fixture.error(LauncherError::PointerInvalid);
    }
    for data in [
        b"{".to_vec(),
        vec![b' '; 8193],
        b"{\"schema\":\"asg.current/v1\",\"schema\":\"asg.current/v1\"}".to_vec(),
    ] {
        fs::write(fixture.prefix.join("current.json"), data).unwrap();
        fixture.error(LauncherError::PointerInvalid);
    }
}

#[test]
fn release_metadata_is_typed_bounded_and_matched_to_pointer() {
    let mut fixture = Fixture::new();
    let baseline = fixture.release.clone();
    for (key, value) in [
        ("schema", json!("asg.version/v2")),
        ("catalog_schema", json!(0)),
        ("control_schema", json!(-1)),
        ("catalog_schema", json!(u64::MAX)),
        ("version", json!("0.2.0-beta.2")),
        ("source_commit", json!("g".repeat(40))),
        ("built_at", json!("2026-02-30T00:00:00Z")),
        ("launcher_protocol_min", json!(0)),
        ("launcher_protocol_max", json!(0)),
        ("unexpected", json!("private-payload")),
    ] {
        fixture.release = baseline.clone();
        fixture.release[key] = value;
        fixture.save();
        fixture.error(LauncherError::ReleaseInvalid);
    }
    fixture.release = baseline;
    fixture.release["target"] = json!("wrong-target");
    fixture.save();
    fixture.error(LauncherError::TargetMismatch);
    fixture.release["target"] = json!(BUILD_TARGET);
    fixture.release["app_sha256"] = json!("0".repeat(64));
    fixture.save();
    fixture.error(LauncherError::IntegrityFailed);
    fs::write(
        fixture.app.parent().unwrap().join("release.json"),
        vec![b' '; 8193],
    )
    .unwrap();
    fixture.error(LauncherError::ReleaseInvalid);
}

#[test]
fn incompatible_protocol_requires_launcher_update() {
    let mut fixture = Fixture::new();
    fixture.pointer["launcher_protocol"] = json!(2);
    fixture.save();
    fixture.error(LauncherError::UpdateRequired);
    fixture.pointer["launcher_protocol"] = json!(1);
    fixture.release["launcher_protocol_min"] = json!(2);
    fixture.release["launcher_protocol_max"] = json!(3);
    fixture.save();
    fixture.error(LauncherError::UpdateRequired);
    fixture.release["launcher_protocol_max"] = json!(1);
    fixture.save();
    fixture.error(LauncherError::ReleaseInvalid);
}

#[test]
fn missing_pointer_release_and_application_have_bounded_failures() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.prefix.join("current.json")).unwrap();
    fixture.error(LauncherError::NotInstalled);
    fixture.save();
    fs::remove_file(fixture.app.parent().unwrap().join("release.json")).unwrap();
    fixture.error(LauncherError::VersionMissing);
    fixture.save();
    fs::remove_file(&fixture.app).unwrap();
    fixture.error(LauncherError::VersionMissing);
    fs::create_dir(&fixture.app).unwrap();
    fixture.error(LauncherError::UnsafePath);
}

#[test]
fn hash_is_checked_on_every_invocation_including_launcher_info() {
    let fixture = Fixture::new();
    assert!(fixture.run(&["--asg-launcher-info"]).status.success());
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&fixture.app)
        .unwrap();
    file.write_all(b"changed").unwrap();
    drop(file);
    fixture.error(LauncherError::IntegrityFailed);
}

#[test]
fn verified_but_non_executable_image_fails_with_exit_five() {
    let mut fixture = Fixture::new();
    fs::write(&fixture.app, b"invalid executable image\n").unwrap();
    let digest = format!("{:x}", Sha256::digest(b"invalid executable image\n"));
    let dir = format!("versions/0.2.0-beta.1-{}", &digest[..12]);
    let previous = fixture.app.parent().unwrap().to_path_buf();
    fs::rename(&previous, fixture.prefix.join(&dir)).unwrap();
    fixture.app = fixture.prefix.join(&dir).join(APP_NAME);
    fixture.pointer["dir"] = json!(dir);
    fixture.pointer["app_sha256"] = json!(digest);
    fixture.release["app_sha256"] = json!(digest);
    fixture.save();
    let output = fixture.run(&["--help"]);
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("{}\n", LauncherError::ExecFailed).as_bytes()
    );
}

fn hex(value: &OsStr) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().map(|b| format!("{b:04x}")).collect()
    }
}

#[test]
fn arguments_cwd_env_and_stdio_are_inherited_without_shell_interpretation() {
    let fixture = Fixture::new();
    let cwd = fixture.prefix.join("working directory");
    fs::create_dir(&cwd).unwrap();
    let mut args: Vec<OsString> = [
        "",
        "--version",
        "--help",
        "mcp",
        "--",
        "--asg-launcher-info",
        "white space",
        "quoted\"text",
        "trailing\\",
        "\\\\\"",
        "line\nline",
        "中文",
        "$HOME & %PATH%",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        args.push(OsString::from_vec(vec![0xff, b'a']));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        args.push(OsString::from_wide(&[0xd800, 0x61]));
    }
    let mut child = Command::new(&fixture.launcher)
        .args(&args)
        .current_dir(&cwd)
        .env("ASG_LAUNCHER_TEST_VALUE", "synthetic environment")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"input\0\nbytes")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let output_text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = output_text.lines().collect();
    #[cfg(unix)]
    assert_eq!(lines[0], format!("pid={pid}"));
    #[cfg(windows)]
    assert_ne!(lines[0], format!("pid={pid}"));
    assert_eq!(
        lines[1],
        format!("cwd={}", hex(cwd.canonicalize().unwrap().as_os_str()))
    );
    assert_eq!(
        lines[2],
        format!("env={}", hex(OsStr::new("synthetic environment")))
    );
    assert_eq!(
        lines[3..3 + args.len()],
        args.iter()
            .map(|a| format!("arg={}", hex(a)))
            .collect::<Vec<_>>()
    );
    assert_eq!(lines.last().unwrap(), &"stdin=696e707574000a6279746573");
    assert_eq!(output.stderr, b"synthetic-stderr\n");
}

#[test]
fn application_exit_status_is_preserved() {
    let fixture = Fixture::new();
    for status in [0, 4, 5, 9, 42, 70, 255] {
        assert_eq!(
            fixture.run(&["exit", &status.to_string()]).status.code(),
            Some(status)
        );
    }
    #[cfg(windows)]
    for status in [259_u32, 0x80000001, 0xc000013a, 0xffffffff] {
        assert_eq!(
            fixture.run(&["exit", &status.to_string()]).status.code(),
            Some(status as i32)
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(fixture.run(&["signal"]).status.signal(), Some(15));
    }
}

#[cfg(unix)]
#[test]
fn symlinks_in_every_install_component_are_rejected() {
    use std::os::unix::fs::symlink;
    for relative in [
        "current.json".to_owned(),
        "versions".to_owned(),
        "VERSION".to_owned(),
        "release.json".to_owned(),
        "APP".to_owned(),
    ] {
        let fixture = Fixture::new();
        let path = match relative.as_str() {
            "VERSION" => fixture.app.parent().unwrap().to_path_buf(),
            "release.json" => fixture.app.parent().unwrap().join("release.json"),
            "APP" => fixture.app.clone(),
            _ => fixture.prefix.join(relative),
        };
        let moved = path.with_file_name("original");
        fs::rename(&path, &moved).unwrap();
        symlink(&moved, &path).unwrap();
        fixture.error(LauncherError::UnsafePath);
    }
}

#[cfg(unix)]
#[test]
fn unix_app_permissions_are_enforced() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    for mode in [0o666, 0o777, 0o664, 0o644] {
        fs::set_permissions(&fixture.app, fs::Permissions::from_mode(mode)).unwrap();
        fixture.error(LauncherError::UnsafePath);
    }
}

#[cfg(windows)]
#[test]
fn junctions_in_version_tree_are_rejected_without_developer_mode() {
    // Junctions need no symlink privilege. Use the native junction operation;
    // all paths are synthetic temporary directories, never host configuration.
    for at_versions in [true, false] {
        let fixture = Fixture::new();
        let original = if at_versions {
            fixture.prefix.join("versions")
        } else {
            fixture.app.parent().unwrap().to_path_buf()
        };
        let relocated = fixture.prefix.join("relocated");
        fs::rename(&original, &relocated).unwrap();
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&original)
            .arg(&relocated)
            .output()
            .unwrap();
        assert!(output.status.success(), "junction fixture creation failed");
        fixture.error(LauncherError::UnsafePath);
        fs::remove_dir(&original).unwrap();
    }
}

#[cfg(windows)]
#[test]
fn verified_application_blocks_replacement_until_drop() {
    let fixture = Fixture::new();
    let verified = verify_installation(&fixture.prefix).unwrap();
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(&fixture.app)
            .is_err()
    );
    assert!(fs::remove_file(&fixture.app).is_err());
    for directory in [
        fixture.app.parent().unwrap(),
        &fixture.prefix.join("versions"),
    ] {
        assert!(fs::rename(directory, fixture.prefix.join("displaced")).is_err());
    }
    drop(verified);
    fs::rename(
        fixture.app.parent().unwrap(),
        fixture.prefix.join("displaced"),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn verified_image_race_child() {
    use std::os::unix::fs::PermissionsExt;
    let Some(prefix) = std::env::var_os("ASG_TEST_VERIFIED_PREFIX") else {
        return;
    };
    let prefix = PathBuf::from(prefix);
    let pointer: Value =
        serde_json::from_slice(&fs::read(prefix.join("current.json")).unwrap()).unwrap();
    let directory = prefix.join(pointer["dir"].as_str().unwrap());
    let app = directory.join(APP_NAME);
    let verified = verify_installation(&prefix).unwrap();
    if std::env::var("ASG_TEST_REPLACE_KIND").unwrap() == "directory" {
        fs::rename(&directory, prefix.join("displaced")).unwrap();
        fs::create_dir(&directory).unwrap();
    } else {
        fs::rename(&app, prefix.join("displaced")).unwrap();
    }
    fs::write(&app, b"unverified replacement image\n").unwrap();
    fs::set_permissions(&app, fs::Permissions::from_mode(0o700)).unwrap();
    let result = verified.launch(&["exit".into(), "37".into()]);
    std::process::exit(result.unwrap_or_else(|error| error.exit_code()));
}

#[cfg(unix)]
#[test]
fn verified_application_never_executes_a_replaced_path() {
    for kind in ["file", "directory"] {
        let fixture = Fixture::new();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "verified_image_race_child", "--nocapture"])
            .env("ASG_TEST_VERIFIED_PREFIX", &fixture.prefix)
            .env("ASG_TEST_REPLACE_KIND", kind)
            .output()
            .unwrap();
        // Linux executes the pinned original; other Unix targets must refuse
        // the changed identity. Neither executes the unverified replacement.
        assert_eq!(
            output.status.code(),
            Some(if cfg!(target_os = "linux") { 37 } else { 9 })
        );
    }
}

#[cfg(windows)]
#[test]
fn isolated_console_driver() {
    use std::io::{BufRead, BufReader};
    use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, SetConsoleCtrlHandler};
    let Some(launcher) = std::env::var_os("ASG_TEST_CONSOLE_LAUNCHER") else {
        return;
    };
    unsafe extern "system" fn driver_handler(event: u32) -> i32 {
        i32::from(event <= 1)
    }
    // The test driver has its own windowless console. Its callback is not the
    // inheritable ignore-Ctrl-C flag and never affects the developer's console.
    assert_ne!(unsafe { SetConsoleCtrlHandler(Some(driver_handler), 1) }, 0);
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = ChildGuard(
        Command::new(launcher)
            .arg("console-events")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "console-ready");
    for (event, expected) in [(0, "handled-1"), (0, "handled-2")] {
        // Group zero broadcasts only within this test's isolated console, to
        // both the waiting launcher and its real, handler-equipped child.
        assert_ne!(unsafe { GenerateConsoleCtrlEvent(event, 0) }, 0);
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), expected);
    }
    line.clear();
    output.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "cleanup-complete");
    assert_eq!(child.0.wait().unwrap().code(), Some(37));
}

#[cfg(windows)]
#[test]
fn real_console_ctrl_c_reaches_child_and_launcher_waits_for_cleanup() {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
    let fixture = Fixture::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "isolated_console_driver", "--nocapture"])
        .env("ASG_TEST_CONSOLE_LAUNCHER", &fixture.launcher)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "console driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
