//! Setup CLI over synthetic installed packages and isolated environment roots.
//! The forwarding launcher is a fixture; actual CLI/config transactions run.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::OnceLock,
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn actual_application_build_info_matches_shipped_catalog_and_control_schemas() {
    let output = Command::new(BIN).arg("__asg-build-info").output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let info: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["schema"], "asg.build-info/v1");
    assert_eq!(info["product"], "agent-session-grep");
    assert_eq!(info["version"], VERSION);
    assert_eq!(info["target"], target());
    assert_eq!(
        info["catalog_schema"],
        agent_session_grep_adapters_sqlite::SCHEMA_VERSION
    );
    assert_eq!(
        info["control_schema"],
        agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION
    );
    assert_eq!(info["launcher_protocol"], 1);
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn app_name() -> &'static str {
    if cfg!(windows) {
        "agent-session-grep.exe"
    } else {
        "agent-session-grep"
    }
}
fn alias() -> &'static str {
    if cfg!(windows) { "asg.exe" } else { "asg" }
}
fn supervisor_name() -> &'static str {
    if cfg!(windows) {
        "asg-supervisor.exe"
    } else {
        "asg-supervisor"
    }
}
fn target() -> &'static str {
    if cfg!(windows) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(target_os = "linux") {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else {
        "x86_64-apple-darwin"
    }
}
fn version_dir() -> String {
    format!(
        "versions/{VERSION}-{}",
        &digest(&fs::read(BIN).unwrap())[..12]
    )
}
fn fixture_launcher() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let app = format!("{}/{}", version_dir(), app_name());
        agent_session_grep_testkit::cached_rustc_fixture(
            &Path::new(env!("CARGO_TARGET_TMPDIR")).join("asg-rustc-fixtures"),
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/setup_command_launcher.rs"),
            app_name(),
            &["--edition=2024"],
            &[("ASG_TEST_APP_RELATIVE", app.as_str())],
        )
    })
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    prefix: PathBuf,
    db: PathBuf,
    home: PathBuf,
    claude: PathBuf,
    codex: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let prefix = root.join("installed candidate");
        let dir = version_dir();
        fs::create_dir_all(prefix.join(&dir)).unwrap();
        fs::copy(BIN, prefix.join(&dir).join(app_name())).unwrap();
        fs::copy(fixture_launcher(), prefix.join(app_name())).unwrap();
        fs::copy(fixture_launcher(), prefix.join(alias())).unwrap();
        let app_hash = digest(&fs::read(BIN).unwrap());
        let pointer = json!({"schema":"asg.current/v1","generation":1,"version":VERSION,"dir":dir,"app":app_name(),"app_sha256":app_hash,"launcher_protocol":1,"activated_at":"2026-10-17T00:00:00Z"});
        let release = json!({"schema":"asg.version/v1","version":VERSION,"target":target(),"source_commit":"a".repeat(40),"app_sha256":app_hash,"catalog_schema":agent_session_grep_adapters_sqlite::SCHEMA_VERSION,"control_schema":agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION,"launcher_protocol_min":1,"launcher_protocol_max":1,"built_at":"2026-10-17T00:00:00Z"});
        fs::write(
            prefix.join("current.json"),
            serde_json::to_vec_pretty(&pointer).unwrap(),
        )
        .unwrap();
        fs::write(
            prefix.join(&dir).join("release.json"),
            serde_json::to_vec_pretty(&release).unwrap(),
        )
        .unwrap();
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
            fs::write(prefix.join(name), b"synthetic fixture content\n").unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                prefix.join("package-install.sh"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let f = Self {
            _temp: temp,
            root: root.clone(),
            prefix,
            db: root.join("data/catalog.db"),
            home: root.join("home"),
            claude: root.join("selected-claude"),
            codex: root.join("selected-codex"),
        };
        f.refresh_manifest();
        f
    }
    fn refresh_manifest(&self) {
        let pointer: Value =
            serde_json::from_slice(&fs::read(self.prefix.join("current.json")).unwrap()).unwrap();
        let dir = pointer["dir"].as_str().unwrap();
        let release: Value =
            serde_json::from_slice(&fs::read(self.prefix.join(dir).join("release.json")).unwrap())
                .unwrap();
        let mut text = format!(
            "asg.package-files/v1\nversion\t{}\ntarget\t{}\nsource_commit\t{}\napp\t{}\napp_sha256\t{}\ndir\t{}\nlauncher_protocol\t1\ncatalog_schema\t{}\ncontrol_schema\t{}\nbuilt_at\t{}\n",
            VERSION,
            release["target"].as_str().unwrap(),
            release["source_commit"].as_str().unwrap(),
            app_name(),
            pointer["app_sha256"].as_str().unwrap(),
            dir,
            release["catalog_schema"],
            release["control_schema"],
            release["built_at"].as_str().unwrap()
        );
        let mut members = BTreeMap::new();
        let supervisor = format!("{dir}/{}", supervisor_name());
        if self.prefix.join(&supervisor).is_file() {
            let content = fs::read(self.prefix.join(&supervisor)).unwrap();
            text.push_str(&format!(
                "supervisor\t{}\nsupervisor_sha256\t{}\n",
                supervisor_name(),
                digest(&content)
            ));
            members.insert(supervisor, (content, "0755"));
        }
        for name in [
            app_name().into(),
            alias().into(),
            format!("{dir}/{}", app_name()),
            format!("{dir}/release.json"),
            "current.json".into(),
            "package-install.ps1".into(),
            "package-install.sh".into(),
            "INSTALL-AND-UPGRADE.md".into(),
            "README.md".into(),
            "CHANGELOG.md".into(),
            "LICENSE-MIT".into(),
            "LICENSE-APACHE".into(),
            "NOTICE".into(),
            "SECURITY.md".into(),
            "THIRD-PARTY-DEPENDENCIES.json".into(),
            "THIRD-PARTY-DEPENDENCIES.csv".into(),
        ] {
            let content = fs::read(self.prefix.join(&name)).unwrap();
            let mode = if name == app_name()
                || name == alias()
                || name == format!("{dir}/{}", app_name())
                || name == "package-install.sh"
            {
                "0755"
            } else {
                "0644"
            };
            members.insert(name, (content, mode));
        }
        for (name, (content, mode)) in members {
            text.push_str(&format!(
                "file\t{}\t{mode}\t{}\t{name}\n",
                digest(&content),
                content.len()
            ));
        }
        fs::write(self.prefix.join("PACKAGE-MANIFEST.tsv"), &text).unwrap();
        let receipt = json!({"schema":"asg.package-install/v1","product":"agent-session-grep","version":VERSION,"target":release["target"],"source_commit":release["source_commit"],"launcher_protocol":1,"manifest_sha256":"b".repeat(64),"archive_sha256":"c".repeat(64),"package_files_sha256":digest(text.as_bytes())});
        fs::write(
            self.prefix.join("package-install.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
    }
    fn command(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .args(["--robot", "--db"])
            .arg(&self.db)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("CLAUDE_CONFIG_DIR", &self.claude)
            .env("CODEX_HOME", &self.codex)
            .env("ASG_ZCODE_CONFIG_ROOT", self.root.join("selected-zcode"))
            .env(
                "ASG_WORKBUDDY_CONFIG_ROOT",
                self.root.join("selected-workbuddy"),
            )
            .env(
                "ASG_ANTIGRAVITY_CONFIG_ROOT",
                self.root.join("selected-antigravity"),
            )
            .env("DSH_HOME", self.root.join("selected-dsh"));
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command(Path::new(BIN))
            .arg("setup")
            .arg("--install-prefix")
            .arg(&self.prefix)
            .args(args)
            .output()
            .unwrap()
    }
    fn data(&self, output: Output, exit: i32) -> Value {
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            !String::from_utf8_lossy(&output.stdout)
                .contains(&self.root.to_string_lossy().to_string())
        );
        value["data"].clone()
    }
    fn no_state(&self) {
        assert!(!self.db.exists());
        assert!(!self.claude.exists());
        assert!(!self.codex.exists());
    }
}

#[test]
fn explicit_hosts_register_repeatedly_and_keep_real_acceptance_pending() {
    let f = Fixture::new();
    let data = f.data(f.run(&["--host", "claude", "--host", "codex"]), 10);
    assert_eq!(data["local_asg"]["mcp_initialized"], true);
    assert_eq!(data["private_receipts_recorded"], true);
    let inventories: Vec<_> = fs::read_dir(f.db.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("setup-hosts-")
                && p.extension().is_some_and(|e| e == "json")
        })
        .collect();
    assert_eq!(inventories.len(), 1);
    let inventory: Value = serde_json::from_slice(&fs::read(&inventories[0]).unwrap()).unwrap();
    assert_eq!(inventory["schema"], "asg.setup-host-inventory/v1");
    assert_eq!(inventory["receipts"].as_array().unwrap().len(), 2);
    for locator in inventory["receipts"].as_array().unwrap() {
        assert!(Path::new(locator["receipt_path"].as_str().unwrap()).is_file());
    }
    assert_eq!(data["hosts"].as_array().unwrap().len(), 2);
    for host in data["hosts"].as_array().unwrap() {
        assert_eq!(host["configuration"], "configured");
        assert_eq!(host["host_handshake"], "pending");
    }
    assert!(f.claude.join(".claude.json").is_file());
    assert!(f.codex.join("config.toml").is_file());
    assert!(!f.home.exists());
    let data = f.data(f.run(&["--host", "claude", "--host", "codex"]), 10);
    for host in data["hosts"].as_array().unwrap() {
        assert_eq!(host["configuration"], "unchanged");
        assert_eq!(host["owned_by_asg"], true);
    }
    let before = fs::read(f.claude.join(".claude.json")).unwrap();
    let mut doc: Value = serde_json::from_slice(&before).unwrap();
    doc["mcpServers"]["agent-session-grep"]["command"] = json!("user-changed");
    let edited = serde_json::to_vec_pretty(&doc).unwrap();
    fs::write(f.claude.join(".claude.json"), &edited).unwrap();
    let data = f.data(f.run(&["--host", "claude"]), 10);
    assert_eq!(data["hosts"][0]["configuration"], "conflict");
    assert_eq!(fs::read(f.claude.join(".claude.json")).unwrap(), edited);
}

#[test]
fn missing_or_ambiguous_flags_never_create_control_or_profiles() {
    let f = Fixture::new();
    for args in [
        vec!["--host"],
        vec!["--host", "unknown"],
        vec!["--host", "claude", "--host", "claude"],
        vec!["--host", "--robot"],
        vec![],
    ] {
        f.data(f.run(&args), 2);
        f.no_state();
    }
}

#[test]
fn package_corruption_wrong_target_and_unknown_pointer_fields_precede_catalog_creation() {
    for failure in [
        "receipt",
        "hash",
        "target",
        "unknown-pointer",
        "missing-member",
        "foreign-launcher",
    ] {
        let f = Fixture::new();
        match failure {
            "receipt" => fs::write(f.prefix.join("package-install.json"), b"{}").unwrap(),
            "hash" => fs::write(f.prefix.join("NOTICE"), b"changed").unwrap(),
            "target" => {
                let path = f.prefix.join(version_dir()).join("release.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["target"] = json!("wrong-target");
                fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
                f.refresh_manifest();
            }
            "unknown-pointer" => {
                let path = f.prefix.join("current.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["unknown"] = json!(true);
                fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
                f.refresh_manifest();
            }
            "missing-member" => fs::remove_file(f.prefix.join("LICENSE-MIT")).unwrap(),
            "foreign-launcher" => {
                fs::write(f.prefix.join(app_name()), [0_u8; 128]).unwrap();
                fs::write(f.prefix.join(alias()), [0_u8; 128]).unwrap();
                f.refresh_manifest();
            }
            _ => unreachable!(),
        }
        f.data(f.run(&["--host", "claude"]), 9);
        f.no_state();
    }
}

#[test]
fn versioned_invocation_resolves_prefix_and_only_selected_host() {
    let f = Fixture::new();
    let installed_app = f.prefix.join(version_dir()).join(app_name());
    let output = f
        .command(&installed_app)
        .args(["setup", "--host", "codex"])
        .output()
        .unwrap();
    let data = f.data(output, 10);
    assert_eq!(data["hosts"][0]["host"], "codex");
    assert!(f.codex.join("config.toml").exists());
    assert!(!f.claude.exists());
}

#[test]
fn no_host_keeps_catalog_only_compatibility_without_installation() {
    let f = Fixture::new();
    let data = f.data(f.command(Path::new(BIN)).arg("setup").output().unwrap(), 10);
    assert_eq!(data["stages"]["catalog"], "ready");
    assert!(f.db.exists());
    assert!(!f.claude.exists());
    assert!(!f.codex.exists());
}

#[test]
fn traversal_and_duplicate_manifest_records_are_rejected_before_write() {
    for failure in ["traversal", "duplicate"] {
        let f = Fixture::new();
        let path = f.prefix.join("PACKAGE-MANIFEST.tsv");
        let mut text = fs::read_to_string(&path).unwrap();
        if failure == "traversal" {
            text = text.replace("\tNOTICE\n", "\t../NOTICE\n");
        } else {
            let record = text
                .lines()
                .find(|s| s.starts_with("file\t"))
                .unwrap()
                .to_string();
            text.push_str(&record);
            text.push('\n');
        }
        fs::write(path, &text).unwrap();
        let receipt_path = f.prefix.join("package-install.json");
        let mut receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        receipt["package_files_sha256"] = json!(digest(text.as_bytes()));
        fs::write(receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        f.data(f.run(&["--host", "claude"]), 9);
        f.no_state();
    }
}

#[test]
fn invalid_profile_override_never_falls_back_to_default_home() {
    let f = Fixture::new();
    let output = f
        .command(Path::new(BIN))
        .arg("setup")
        .arg("--install-prefix")
        .arg(&f.prefix)
        .args(["--host", "claude"])
        .env("CLAUDE_CONFIG_DIR", "relative-profile")
        .output()
        .unwrap();
    let data = f.data(output, 10);
    assert_eq!(data["stages"]["host_registration"], "not_attempted");
    assert_eq!(data["local_asg"]["status"], "failed");
    assert!(!f.home.exists());
    assert!(!f.claude.exists());
    assert!(!f.codex.exists());
}

#[test]
fn verified_supervisor_package_and_later_pointer_generation_respect_autostart_optout() {
    let f = Fixture::new();
    fs::copy(
        env!("CARGO_BIN_EXE_asg-supervisor"),
        f.prefix.join(version_dir()).join(supervisor_name()),
    )
    .unwrap();
    let pointer_path = f.prefix.join("current.json");
    let mut pointer: Value = serde_json::from_slice(&fs::read(&pointer_path).unwrap()).unwrap();
    pointer["generation"] = json!(2);
    fs::write(pointer_path, serde_json::to_vec(&pointer).unwrap()).unwrap();
    f.refresh_manifest();
    let data = f.data(f.run(&["--host", "claude", "--no-autostart"]), 10);
    assert_eq!(data["local_asg"]["mcp_initialized"], true);
    assert_eq!(data["autostart"]["reason"], "explicit_opt_out");
    let control = agent_session_grep_adapters_sqlite::SqliteControlStore::open_current_read_only(
        f.db.parent().unwrap(),
    )
    .unwrap();
    use agent_session_grep_ports::control::ControlStore;
    assert!(!control.status().unwrap().autostart_enabled);
    assert!(!f.db.parent().unwrap().join("native-autostart").exists());
}

#[test]
fn supervisor_manifest_or_gui_identity_mismatch_precedes_catalog_and_profiles() {
    for mismatch in ["hash", "image"] {
        let f = Fixture::new();
        let target = f.prefix.join(version_dir()).join(supervisor_name());
        fs::copy(env!("CARGO_BIN_EXE_asg-supervisor"), &target).unwrap();
        f.refresh_manifest();
        if mismatch == "hash" {
            fs::write(&target, b"changed supervisor").unwrap();
        } else {
            fs::copy(BIN, &target).unwrap();
            f.refresh_manifest();
        }
        let output = f.run(&["--host", "claude", "--no-autostart"]);
        if mismatch == "image" && !cfg!(windows) {
            continue;
        }
        f.data(output, 9);
        f.no_state();
    }
}

#[test]
fn replacement_during_actual_mcp_probe_preserves_a_stages_without_b_or_host_writes() {
    use agent_session_grep_adapters_sqlite::{SqliteControlStore, managed_store::ManagedStore};
    use agent_session_grep_ports::control::{ControlId, ControlStore, DesiredUpdates};
    let f = Fixture::new();
    let replacement = f.root.join("replacement-data");
    let control = SqliteControlStore::create(
        &replacement,
        &ControlId::parse("replacement-installation").unwrap(),
        DesiredUpdates::Paused,
    )
    .unwrap();
    drop(
        ManagedStore::create(
            &replacement.join("catalog.db"),
            &control,
            ControlId::parse("replacement-catalog").unwrap(),
            1,
        )
        .unwrap(),
    );
    let before = control.status().unwrap();
    drop(control);
    let before_control = fs::read(SqliteControlStore::path(&replacement)).unwrap();
    let before_catalog = fs::read(replacement.join("catalog.db")).unwrap();
    let before_files: std::collections::BTreeSet<_> = fs::read_dir(&replacement)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();

    // A test-only launcher waits for the real MCP child to finish, replaces the
    // physical root, then delivers its successful initialize frame to setup.
    // Production has no environment or timing hook for this scenario.
    let source = f.root.join("probe-race.rs");
    fs::write(&source, r#"
use std::{io::{Read, Write}, path::Path, process::{Command, Stdio}};
fn main() {
    let exe = std::env::current_exe().unwrap();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut child = Command::new(exe.parent().unwrap().join(env!("ASG_TEST_APP_RELATIVE")))
        .args(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut input = Vec::new(); std::io::stdin().read_to_end(&mut input).unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    if args.last().is_some_and(|v| v == "mcp") && output.status.success() {
        let root = Path::new(env!("ASG_TEST_ROOT"));
        std::fs::rename(root.join("data"), root.join("original-data")).unwrap();
        std::fs::rename(root.join("replacement-data"), root.join("data")).unwrap();
    }
    std::io::stdout().write_all(&output.stdout).unwrap();
    std::process::exit(output.status.code().unwrap_or(70));
}
"#).unwrap();
    let binary = f.root.join(alias());
    let compiled = Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .env(
            "ASG_TEST_APP_RELATIVE",
            format!("{}/{}", version_dir(), app_name()),
        )
        .env("ASG_TEST_ROOT", &f.root)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "synthetic probe helper failed to compile"
    );
    fs::copy(&binary, f.prefix.join(app_name())).unwrap();
    fs::copy(&binary, f.prefix.join(alias())).unwrap();
    f.refresh_manifest();
    let data = f.data(
        f.run(&["--host", "claude", "--host", "codex", "--no-autostart"]),
        10,
    );
    assert_eq!(data["stages"]["catalog"], "ready");
    assert_eq!(data["local_asg"]["mcp_initialized"], true);
    assert_eq!(data["recovery"], "setup_identity_changed");
    assert_eq!(data["autostart"]["reason"], "setup_identity_changed");
    assert_eq!(data["private_receipt_count"], 0);
    assert!(!f.claude.exists() && !f.codex.exists());
    assert_eq!(
        fs::read(SqliteControlStore::path(f.db.parent().unwrap())).unwrap(),
        before_control
    );
    assert_eq!(fs::read(&f.db).unwrap(), before_catalog);
    assert_eq!(
        fs::read_dir(f.db.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>(),
        before_files
    );
    let current = SqliteControlStore::open_current_read_only(f.db.parent().unwrap()).unwrap();
    let after = current.status().unwrap();
    assert_eq!(after.policy.installation_id, before.policy.installation_id);
    assert_eq!(after.policy.control_seq, before.policy.control_seq);
    assert_eq!(after.autostart_enabled, before.autostart_enabled);
}

#[test]
fn explicit_history_setup_selects_only_requested_root_and_keeps_paused_intent() {
    let f = Fixture::new();
    let history = f.root.join("chosen history");
    let unselected = f.root.join("other history");
    fs::create_dir(&history).unwrap();
    fs::create_dir(&unselected).unwrap();
    let bytes = br#"{"type":"user","uuid":"setup-original","sessionId":"setup-history","message":{"role":"user","content":"setup selected original evidence"}}"#;
    fs::write(history.join("history.jsonl"), bytes).unwrap();
    fs::write(unselected.join("sentinel.jsonl"), b"must not be read").unwrap();
    f.data(f.run(&["--host", "claude", "--no-autostart"]), 10);
    let paused = f
        .command(Path::new(BIN))
        .args(["background", "pause"])
        .output()
        .unwrap();
    // No worker has run yet, so the pause transition completes immediately.
    assert_eq!(paused.status.code(), Some(0));
    let output = f
        .command(Path::new(BIN))
        .args([
            "setup",
            "--host",
            "claude",
            "--no-autostart",
            "--install-prefix",
        ])
        .arg(&f.prefix)
        .args(["--history", "claude"])
        .arg(&history)
        .output()
        .unwrap();
    let data = f.data(output, 10);
    assert_eq!(data["history_selection"]["status"], "selected");
    assert_eq!(
        data["history_selection"]["selections"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(data["background_start"]["reason"], "paused");
    use agent_session_grep_adapters_sqlite::SqliteControlStore;
    use agent_session_grep_ports::control::{ControlStore, DesiredUpdates};
    let control = SqliteControlStore::open_current_read_only(f.db.parent().unwrap()).unwrap();
    let status = control.status().unwrap();
    assert_eq!(status.desired_updates, DesiredUpdates::Paused);
    assert_eq!(status.policy.selections.len(), 1);
    assert_eq!(
        status.policy.selections[0].region.locator,
        agent_session_grep_ports::control::CanonicalLocator::from_path(
            &history.canonicalize().unwrap()
        )
        .unwrap()
    );
    assert_eq!(fs::read(history.join("history.jsonl")).unwrap(), bytes);
    assert_eq!(
        fs::read(unselected.join("sentinel.jsonl")).unwrap(),
        b"must not be read"
    );
}

#[test]
fn invalid_history_or_unselected_provider_has_no_setup_side_effects() {
    let f = Fixture::new();
    let history = f.root.join("history");
    fs::create_dir(&history).unwrap();
    for (host, provider, root) in [
        ("claude", "codex", history.clone()),
        ("claude", "claude", f.root.join("missing")),
    ] {
        let output = f
            .command(Path::new(BIN))
            .args(["setup", "--host", host, "--install-prefix"])
            .arg(&f.prefix)
            .args(["--history", provider])
            .arg(root)
            .output()
            .unwrap();
        assert!(matches!(output.status.code(), Some(2 | 5)));
        f.no_state();
    }
}

#[test]
fn current_schema_six_host_setup_preserves_fallback_and_paused_history_selection() {
    use agent_session_grep_adapters_sqlite::{SqliteControlStore, managed_store::ManagedStore};
    use agent_session_grep_ports::control::{
        CanonicalLocator, ControlId, ControlStore, DesiredUpdates,
    };
    let f = Fixture::new();
    let release: Value = serde_json::from_slice(
        &fs::read(f.prefix.join(version_dir()).join("release.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        release["catalog_schema"],
        agent_session_grep_adapters_sqlite::SCHEMA_VERSION
    );
    assert_eq!(
        release["control_schema"],
        agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION
    );
    let control = SqliteControlStore::create(
        f.db.parent().unwrap(),
        &ControlId::parse("six-host-setup-installation").unwrap(),
        DesiredUpdates::Paused,
    )
    .unwrap();
    drop(
        ManagedStore::create(
            &f.db,
            &control,
            ControlId::parse("six-host-setup-catalog").unwrap(),
            1,
        )
        .unwrap(),
    );
    drop(control);
    let fallback = f.home.join(".agents/mcp.json");
    fs::create_dir_all(fallback.parent().unwrap()).unwrap();
    let generic = serde_json::json!({"mcpServers": {
        "external": {"command":"other", "args":["spaces 中文"],
            "env":{"SYNTHETIC_FIELD":"preserve"}, "enable":false}
    }});
    let generic_bytes = serde_json::to_vec_pretty(&generic).unwrap();
    fs::write(&fallback, &generic_bytes).unwrap();
    let mut command = f.command(Path::new(BIN));
    command
        .args(["setup", "--no-autostart", "--install-prefix"])
        .arg(&f.prefix);
    let mut histories = Vec::new();
    for (host, provider) in [
        ("claude", "claude-code"),
        ("codex", "codex"),
        ("zcode", "zcode"),
        ("workbuddy", "workbuddy"),
        ("antigravity", "antigravity"),
        ("deepseek-harness", "deepseek-harness"),
    ] {
        let root = f.root.join(format!("synthetic {provider} history"));
        fs::create_dir(&root).unwrap();
        let bytes = format!("synthetic untouched {provider} sentinel").into_bytes();
        fs::write(root.join("sentinel"), &bytes).unwrap();
        command
            .args(["--host", host, "--history", provider])
            .arg(&root);
        histories.push((provider, root, bytes));
    }
    let data = f.data(command.output().unwrap(), 10);
    assert_eq!(data["local_asg"]["mcp_initialized"], true);
    assert_eq!(
        data["history_selection"]["status"],
        "selected",
        "content-free setup stages: history={}, host_count={}, background={}",
        data["history_selection"],
        data["hosts"].as_array().unwrap().len(),
        data["background_start"]
    );
    assert_eq!(
        data["history_selection"]["selections"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert_eq!(data["background_start"]["reason"], "paused");
    assert_eq!(data["autostart"]["reason"], "explicit_opt_out");
    assert_eq!(data["hosts"].as_array().unwrap().len(), 6);
    for host in data["hosts"].as_array().unwrap() {
        assert_eq!(host["configuration"], "configured");
        assert_eq!(host["owned_by_asg"], true);
        assert_eq!(host["host_handshake"], "pending");
    }
    let native: Value =
        serde_json::from_slice(&fs::read(f.root.join("selected-zcode/cli/config.json")).unwrap())
            .unwrap();
    assert_eq!(
        native["mcp"]["servers"]["external"],
        generic["mcpServers"]["external"]
    );
    assert!(native["mcp"]["servers"]["agent-session-grep"].is_object());
    assert_eq!(fs::read(&fallback).unwrap(), generic_bytes);
    let repeat = f.data(command.output().unwrap(), 10);
    assert_eq!(
        repeat["history_selection"]["status"],
        "selected",
        "content-free repeat stages: status={}, recovery={}, local={}, history={}, autostart={}, stages={}",
        repeat["status"],
        repeat["recovery"],
        repeat["local_asg"],
        repeat["history_selection"],
        repeat["autostart"],
        repeat["stages"]
    );
    assert_eq!(repeat["background_start"]["reason"], "paused");
    for host in repeat["hosts"].as_array().unwrap() {
        assert_eq!(host["configuration"], "unchanged");
        assert_eq!(host["host_handshake"], "pending");
    }
    let control = SqliteControlStore::open_current_read_only(f.db.parent().unwrap()).unwrap();
    let state = control.status().unwrap();
    assert_eq!(state.desired_updates, DesiredUpdates::Paused);
    assert!(!state.autostart_enabled);
    assert_eq!(state.policy.selections.len(), 6);
    for (provider, root, bytes) in histories {
        let selection = state
            .policy
            .selections
            .iter()
            .find(|s| s.region.provider.as_str() == provider)
            .unwrap();
        assert!(selection.enabled);
        assert_eq!(
            selection.region.locator,
            CanonicalLocator::from_path(&root.canonicalize().unwrap()).unwrap()
        );
        assert_eq!(fs::read(root.join("sentinel")).unwrap(), bytes);
    }
    assert_eq!(fs::read(&fallback).unwrap(), generic_bytes);
    assert!(!f.db.parent().unwrap().join("native-autostart").exists());
}

#[test]
fn explicit_historical_package_schemas_are_rejected_before_any_setup_write() {
    for field in ["catalog_schema", "control_schema"] {
        let f = Fixture::new();
        let path = f.prefix.join(version_dir()).join("release.json");
        let mut release: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // These are deliberately historical package fixtures, not the schema
        // emitted by the current-source synthetic package builder.
        release[field] = json!(1);
        fs::write(path, serde_json::to_vec_pretty(&release).unwrap()).unwrap();
        f.refresh_manifest();
        f.data(f.run(&["--host", "claude", "--no-autostart"]), 9);
        f.no_state();
        assert!(!f.home.exists());
    }
}
