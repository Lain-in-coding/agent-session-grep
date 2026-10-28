use super::*;
use std::sync::OnceLock;

fn fixture_binary() -> &'static Path {
    static BINARY: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &BINARY
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let binary = dir.path().join(if cfg!(windows) {
                "setup-fixture.exe"
            } else {
                "setup-fixture"
            });
            let source =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/setup_hosts_app.rs");
            let output = std::process::Command::new("rustc")
                .arg("--edition=2024")
                .arg(source)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture compilation: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            (dir, binary)
        })
        .1
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    request: SetupHostsRequest,
}
impl Fixture {
    fn new(hosts: Vec<Host>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let launcher = root.join(if cfg!(windows) {
            "local app with spaces.exe"
        } else {
            "local app with spaces"
        });
        fs::copy(fixture_binary(), &launcher).unwrap();
        let catalog = root.join("synthetic catalog.db");
        fs::write(&catalog, b"synthetic protocol fixture, no histories").unwrap();
        let expected_identity = ExpectedAsgIdentity {
            version: "0.1.0-fixture".into(),
            launcher_sha256: digest_file(&File::open(&launcher).unwrap()).unwrap(),
        };
        let profiles = ProfileRoots {
            home: root.join("profile"),
            claude_config_dir: None,
            codex_home: None,
            ..ProfileRoots::default()
        };
        Self {
            _dir: dir,
            root,
            request: SetupHostsRequest {
                launcher,
                catalog,
                selected_hosts: hosts,
                expected_identity,
                profiles: Some(profiles),
                create_missing_parents: true,
            },
        }
    }
    fn path(&self, host: Host) -> PathBuf {
        config_path(host, self.request.profiles.as_ref().unwrap()).unwrap()
    }
    fn write(&self, host: Host, text: &str) {
        let path = self.path(host);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn run(&self) -> SetupHostsReport {
        setup_selected_hosts(&self.request).unwrap()
    }
    fn mode(&self, value: &str) {
        fs::write(self.request.launcher.with_extension("mode"), value).unwrap();
    }
}

#[test]
fn default_and_override_paths_are_explicit_and_absolute() {
    let f = Fixture::new(vec![Host::ClaudeCode]);
    let p = f.request.profiles.as_ref().unwrap();
    assert_eq!(
        config_path(Host::ClaudeCode, p).unwrap(),
        p.home.join(".claude.json")
    );
    assert_eq!(
        config_path(Host::Codex, p).unwrap(),
        p.home.join(".codex/config.toml")
    );
    let p = ProfileRoots {
        home: f.root.join("ignored"),
        claude_config_dir: Some(f.root.join("claude-override")),
        codex_home: Some(f.root.join("codex-override")),
        ..ProfileRoots::default()
    };
    assert_eq!(
        config_path(Host::ClaudeCode, &p).unwrap(),
        f.root.join("claude-override/.claude.json")
    );
    assert_eq!(
        config_path(Host::Codex, &p).unwrap(),
        f.root.join("codex-override/config.toml")
    );
    let p = ProfileRoots {
        claude_config_dir: Some("relative".into()),
        ..p
    };
    assert_eq!(
        config_path(Host::ClaudeCode, &p).unwrap_err().code,
        SetupHostsErrorCode::InvalidPath
    );
}

#[test]
fn empty_and_duplicate_choices_fail_before_probe_or_profile_creation() {
    let mut f = Fixture::new(vec![]);
    f.mode("hang");
    for hosts in [vec![], vec![Host::Codex, Host::Codex]] {
        f.request.selected_hosts = hosts;
        assert_eq!(
            setup_selected_hosts(&f.request).err().unwrap().code,
            SetupHostsErrorCode::InvalidSelection
        );
        assert!(!f.root.join("profile").exists());
    }
}

#[test]
fn both_hosts_preserve_unrelated_settings_and_reuse_owned_receipts() {
    let f = Fixture::new(vec![Host::ClaudeCode, Host::Codex]);
    f.write(
        Host::ClaudeCode,
        r#"{"theme":"dark","mcpServers":{"other":{"command":"other"}}}"#,
    );
    f.write(Host::Codex,"# keep top comment\nmodel = 'synthetic' # keep inline\n[mcp_servers.other]\ncommand = 'other'\n");
    let first = f.run();
    assert!(first.local_asg.version_verified && first.local_asg.mcp_initialized);
    assert_eq!(first.hosts.len(), 2);
    for host in &first.hosts {
        assert_eq!(host.configuration, ConfigurationStage::Configured);
        assert!(host.owned_by_asg);
        assert_eq!(host.host_handshake, HostHandshakeStage::Pending);
    }
    for receipt in &first.private_receipts {
        assert!(receipt.read_receipt().unwrap().owned_by_asg);
    }
    let toml = fs::read_to_string(f.path(Host::Codex)).unwrap();
    assert!(
        toml.contains("# keep top comment")
            && toml.contains("# keep inline")
            && toml.contains("command = 'other'")
    );
    let json: Value = serde_json::from_slice(&fs::read(f.path(Host::ClaudeCode)).unwrap()).unwrap();
    assert_eq!(json["theme"], "dark");
    assert_eq!(json["mcpServers"]["other"]["command"], "other");
    let second = f.run();
    for host in &second.hosts {
        assert_eq!(host.configuration, ConfigurationStage::Unchanged);
        assert!(host.owned_by_asg);
    }
    for receipt in &second.private_receipts {
        assert!(receipt.read_receipt().unwrap().owned_by_asg);
        assert!(
            first
                .private_receipts
                .iter()
                .all(|old| old.transaction_id != receipt.transaction_id)
        );
        let store = HostConfigStore::open(
            &receipt.config_path,
            &receipt.transaction_root,
            receipt.host,
        )
        .unwrap();
        assert_eq!(store.inspect_recovery().unwrap().len(), 2);
        store.remove(&receipt.read_receipt().unwrap()).unwrap();
    }
}

#[test]
fn setup_recovers_host_config_exchange_before_rebuilding_receipts() {
    use crate::host_config::TestPoint as HostTestPoint;

    let f = Fixture::new(vec![Host::ClaudeCode]);
    f.write(Host::ClaudeCode, r#"{"preserve":true,"theme":"synthetic"}"#);
    let config = f.path(Host::ClaudeCode);
    let root = transaction_root(&config, Host::ClaudeCode).unwrap();
    let store = HostConfigStore::open(&config, &root, Host::ClaudeCode).unwrap();
    let registration = McpRegistration::new(
        f.request.launcher.to_str().unwrap().into(),
        vec![
            "--db".into(),
            f.request.catalog.to_str().unwrap().into(),
            "mcp".into(),
        ],
    )
    .unwrap();
    let error = store
        .change_with_test_hook(
            Some(registration.value(Host::ClaudeCode)),
            None,
            &mut |point| {
                if matches!(point, HostTestPoint::Exchanged) {
                    Err(ConfigErrorCode::Io.into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ConfigErrorCode::Io);
    assert_eq!(store.inspect_recovery().unwrap()[0].phase, Phase::Exchanged);
    drop(store);

    let report = f.run();
    assert_eq!(report.hosts[0].configuration, ConfigurationStage::Unchanged);
    assert!(report.hosts[0].owned_by_asg);
    let value: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    assert_eq!(value["preserve"], true);
    assert_eq!(value["theme"], "synthetic");
    assert_eq!(
        value["mcpServers"]["agent-session-grep"]["command"],
        f.request.launcher.to_str().unwrap()
    );
    assert_eq!(report.private_receipts.len(), 1);
    assert!(
        report.private_receipts[0]
            .read_receipt()
            .unwrap()
            .owned_by_asg
    );
}

#[test]
fn only_selected_host_is_created_and_missing_parent_needs_explicit_permission() {
    let mut f = Fixture::new(vec![Host::ClaudeCode]);
    f.request.create_missing_parents = false;
    assert_eq!(f.run().hosts[0].configuration, ConfigurationStage::Failed);
    assert!(!f.root.join("profile").exists());
    f.request.create_missing_parents = true;
    assert_eq!(
        f.run().hosts[0].configuration,
        ConfigurationStage::Configured
    );
    assert!(!f.path(Host::Codex).parent().unwrap().exists());
}

#[test]
fn edited_owned_key_is_preserved_as_conflict() {
    let f = Fixture::new(vec![Host::ClaudeCode]);
    assert_eq!(
        f.run().hosts[0].configuration,
        ConfigurationStage::Configured
    );
    let mut doc: Value =
        serde_json::from_slice(&fs::read(f.path(Host::ClaudeCode)).unwrap()).unwrap();
    doc["mcpServers"]["agent-session-grep"]["command"] = json!("user-changed");
    let bytes = serde_json::to_vec_pretty(&doc).unwrap();
    fs::write(f.path(Host::ClaudeCode), &bytes).unwrap();
    let report = f.run();
    assert_eq!(report.hosts[0].configuration, ConfigurationStage::Conflict);
    assert_eq!(report.private_receipts.len(), 1);
    assert!(
        report.private_receipts[0]
            .read_receipt()
            .unwrap()
            .owned_by_asg
    );
    assert_eq!(fs::read(f.path(Host::ClaudeCode)).unwrap(), bytes);
}

#[test]
fn identical_preexisting_registration_is_never_adopted() {
    let f = Fixture::new(vec![Host::ClaudeCode]);
    let node = json!({"mcpServers":{"agent-session-grep":{"type":"stdio","command":f.request.launcher,"args":["--db",f.request.catalog,"mcp"]}}});
    f.write(Host::ClaudeCode, &node.to_string());
    for _ in 0..2 {
        let report = f.run();
        assert_eq!(report.hosts[0].configuration, ConfigurationStage::Unchanged);
        assert!(!report.hosts[0].owned_by_asg);
        let loc = &report.private_receipts[0];
        assert_eq!(
            HostConfigStore::open(&loc.config_path, &loc.transaction_root, loc.host)
                .unwrap()
                .remove(&loc.read_receipt().unwrap())
                .unwrap_err()
                .code,
            ConfigErrorCode::Unowned
        );
    }
}

#[test]
fn malformed_and_unowned_hosts_do_not_block_other_selected_host() {
    for (text, expected) in [
        ("{broken", ConfigurationStage::Malformed),
        (
            r#"{"mcpServers":{"agent-session-grep":{"command":"other"}}}"#,
            ConfigurationStage::Unowned,
        ),
    ] {
        let f = Fixture::new(vec![Host::ClaudeCode, Host::Codex]);
        f.write(Host::ClaudeCode, text);
        let report = f.run();
        assert_eq!(report.hosts[0].configuration, expected);
        assert_eq!(
            report.hosts[1].configuration,
            ConfigurationStage::Configured
        );
        assert_eq!(fs::read_to_string(f.path(Host::ClaudeCode)).unwrap(), text);
    }
}

#[test]
fn lost_composition_receipt_recovers_from_verified_journal_but_corrupt_receipt_blocks() {
    let f = Fixture::new(vec![Host::ClaudeCode]);
    let first = f.run();
    let loc = &first.private_receipts[0];
    fs::remove_file(&loc.receipt_path).unwrap();
    let second = f.run();
    assert_eq!(second.hosts[0].configuration, ConfigurationStage::Unchanged);
    assert!(second.hosts[0].owned_by_asg);
    let loc = &second.private_receipts[0];
    fs::write(&loc.receipt_path, b"{corrupt").unwrap();
    let before = fs::read(&loc.config_path).unwrap();
    assert_eq!(
        f.run().hosts[0].configuration,
        ConfigurationStage::RecoveryRequired
    );
    assert_eq!(fs::read(&loc.config_path).unwrap(), before);
}

#[test]
fn unrelated_host_edit_survives_repeat_and_removal() {
    let f = Fixture::new(vec![Host::Codex]);
    f.run();
    let path = f.path(Host::Codex);
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("\n[unrelated]\nmarker = 'private synthetic' # preserve\n");
    fs::write(&path, &text).unwrap();
    let report = f.run();
    assert_eq!(report.hosts[0].configuration, ConfigurationStage::Unchanged);
    assert_eq!(fs::read_to_string(&path).unwrap(), text);
    let loc = &report.private_receipts[0];
    HostConfigStore::open(&loc.config_path, &loc.transaction_root, loc.host)
        .unwrap()
        .remove(&loc.read_receipt().unwrap())
        .unwrap();
    assert!(
        fs::read_to_string(path)
            .unwrap()
            .contains("marker = 'private synthetic' # preserve")
    );
}

#[test]
fn malformed_or_incomplete_journal_stops_before_another_edit() {
    for mutation in ["prepared", "missing-parent"] {
        let f = Fixture::new(vec![Host::Codex]);
        let report = f.run();
        let loc = &report.private_receipts[0];
        let directory = loc.receipt_path.parent().unwrap();
        let path = fs::read_dir(directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("state-")
                    && p.extension().is_some_and(|e| e == "json")
            })
            .max()
            .unwrap();
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if mutation == "prepared" {
            value["phase"] = json!("prepared");
        } else {
            value["previous_receipt"] = json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let before = fs::read(&loc.config_path).unwrap();
        let stage = f.run().hosts[0].configuration;
        assert_eq!(stage, ConfigurationStage::RecoveryRequired, "{mutation}");
        assert_eq!(fs::read(&loc.config_path).unwrap(), before);
    }
}

#[test]
fn identity_and_protocol_failures_never_write_profiles_or_leak_output() {
    for mode in ["wrong-version", "bad-mcp", "stderr"] {
        let f = Fixture::new(vec![Host::ClaudeCode]);
        f.mode(mode);
        let error = setup_selected_hosts(&f.request).err().unwrap();
        assert!(!f.root.join("profile").exists());
        let message = format!("{error:?} {error}");
        assert!(
            !message.contains("synthetic-private-marker")
                && !message.contains(&f.root.to_string_lossy().to_string())
        );
    }
    let mut f = Fixture::new(vec![Host::ClaudeCode]);
    f.request.expected_identity.launcher_sha256 = "0".repeat(64);
    assert_eq!(
        setup_selected_hosts(&f.request).err().unwrap().code,
        SetupHostsErrorCode::IdentityMismatch
    );
    assert!(!f.root.join("profile").exists());
}

#[cfg(windows)]
#[test]
fn local_check_allows_catalog_sharing_during_background_write() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let f = Fixture::new(vec![Host::ClaudeCode]);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let _worker_catalog_handle = options.open(&f.request.catalog).unwrap();

    let checked = check_local_asg(
        &f.request.launcher,
        &f.request.catalog,
        &f.request.expected_identity,
    )
    .expect("setup self-check must coexist with an active catalog writer");
    assert!(checked.version_verified);
    assert!(checked.mcp_initialized);
}

#[test]
fn probe_budget_caps_output_and_reaps_descendants() {
    for mode in ["flood", "hang", "tree"] {
        let f = Fixture::new(vec![Host::ClaudeCode]);
        f.mode(mode);
        let start = Instant::now();
        let error = probe_with_timeout(
            &f.request.launcher,
            &[OsStr::new("--version")],
            b"",
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(matches!(
            error.code,
            SetupHostsErrorCode::ProbeFailed | SetupHostsErrorCode::ProbeTimeout
        ));
        assert!(start.elapsed() < Duration::from_secs(3));
        if mode == "tree" {
            std::thread::sleep(Duration::from_millis(2200));
            assert!(!f.request.launcher.with_extension("escaped").exists());
        }
    }
}

#[test]
fn public_summary_contains_no_private_paths_or_receipts() {
    let f = Fixture::new(vec![Host::ClaudeCode]);
    let report = f.run();
    let summary = serde_json::to_value(&report.hosts).unwrap();
    assert_eq!(summary[0]["host_handshake"], "pending");
    assert_eq!(summary[0].as_object().unwrap().len(), 4);
    assert!(
        !summary
            .to_string()
            .contains(&f.root.to_string_lossy().to_string())
    );
    assert!(
        !summary
            .to_string()
            .contains(&report.private_receipts[0].transaction_id)
    );
}

#[test]
fn forged_receipt_locator_is_refused() {
    let f = Fixture::new(vec![Host::ClaudeCode]);
    let mut report = f.run();
    let locator = &mut report.private_receipts[0];
    locator.transaction_id = "../outside".into();
    assert_eq!(
        locator.read_receipt().unwrap_err().code,
        SetupHostsErrorCode::RecoveryRequired
    );
}

#[test]
fn distinct_successful_roots_are_ambiguous_and_do_not_guess_ownership() {
    let f = Fixture::new(vec![Host::Codex]);
    let report = f.run();
    let locator = &report.private_receipts[0];
    let registration = McpRegistration::new(
        f.request.launcher.to_str().unwrap().into(),
        vec![
            "--db".into(),
            f.request.catalog.to_str().unwrap().into(),
            "mcp".into(),
        ],
    )
    .unwrap();
    let store = HostConfigStore::open(
        &locator.config_path,
        &locator.transaction_root,
        locator.host,
    )
    .unwrap();
    // An independent successful no-op without the prior receipt is unowned.
    let second = store.install(&registration, None).unwrap();
    assert!(!second.owned_by_asg);
    let before = fs::read(&locator.config_path).unwrap();
    let conflict = f.run();
    assert_eq!(
        conflict.hosts[0].configuration,
        ConfigurationStage::RecoveryRequired
    );
    assert_eq!(conflict.private_receipts.len(), 2);
    assert_eq!(fs::read(&locator.config_path).unwrap(), before);
}

#[cfg(windows)]
#[test]
fn junction_parent_creation_is_refused_without_writing_its_target() {
    let f = Fixture::new(vec![Host::Codex]);
    let target = f.root.join("redirect-parent");
    fs::create_dir(&target).unwrap();
    let link = f.root.join("junction");
    let output = std::process::Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "could not create synthetic junction"
    );
    assert!(ensure_parent(&link.join("not-created"), true).is_err());
    assert!(!target.join("not-created").exists());
    // Remove only the fixture junction entry, never traverse its target.
    fs::remove_dir(link).unwrap();
}

#[cfg(unix)]
#[test]
fn existing_config_symlink_is_preserved_and_new_parent_link_is_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new(vec![Host::ClaudeCode]);
    let target = f.root.join("redirect.json");
    fs::write(&target, b"{}").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
    fs::create_dir_all(f.path(Host::ClaudeCode).parent().unwrap()).unwrap();
    symlink(&target, f.path(Host::ClaudeCode)).unwrap();
    let report = f.run();
    assert_eq!(
        report.hosts[0].configuration,
        ConfigurationStage::Configured
    );
    assert!(
        fs::symlink_metadata(f.path(Host::ClaudeCode))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let link = f.root.join("parent-link");
    symlink(&f.root, &link).unwrap();
    assert!(ensure_parent(&link.join("not-created"), true).is_err());
    assert!(!f.root.join("not-created").exists());
}

#[test]
fn shared_local_capture_preserves_warning_failure_and_a_single_caller_deadline() {
    for mode in ["stderr", "failure"] {
        let f = Fixture::new(vec![Host::ClaudeCode]);
        f.mode(mode);
        let capture = capture_local(
            &f.request.launcher,
            &[OsStr::new("capture-fixture")],
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(capture.success, mode != "failure");
        assert_eq!(capture.stdout, b"synthetic local manager output\n");
        assert_eq!(!capture.stderr.is_empty(), mode == "stderr");
    }
    let f = Fixture::new(vec![Host::ClaudeCode]);
    f.mode("hang");
    let start = Instant::now();
    assert_eq!(
        capture_local(&f.request.launcher, &[OsStr::new("capture-fixture")], start)
            .err()
            .unwrap()
            .code,
        SetupHostsErrorCode::ProbeTimeout
    );
    assert!(start.elapsed() < Duration::from_millis(100));
    let start = Instant::now();
    assert_eq!(
        capture_local(
            &f.request.launcher,
            &[OsStr::new("capture-fixture")],
            start + Duration::from_millis(200)
        )
        .err()
        .unwrap()
        .code,
        SetupHostsErrorCode::ProbeTimeout
    );
    assert!(start.elapsed() < Duration::from_secs(3));
}
#[test]
fn remove_owned_registration_preserves_unrelated_settings_and_retries_receipt() {
    let fixture = Fixture::new(vec![Host::ClaudeCode]);
    fixture.write(Host::ClaudeCode, r#"{"unrelated":{"theme":"amber"}}"#);
    let report = fixture.run();
    let locator = &report.private_receipts[0];
    let expected = McpRegistration::new(
        fixture.request.launcher.to_str().unwrap().into(),
        vec![
            "--db".into(),
            fixture.request.catalog.to_str().unwrap().into(),
            "mcp".into(),
        ],
    )
    .unwrap();
    let receipt =
        remove_owned_registration(locator, &expected, Instant::now() + Duration::from_secs(5))
            .unwrap();
    assert_eq!(receipt.status, crate::host_config::EditStatus::Removed);
    let content: Value = serde_json::from_slice(&fs::read(&locator.config_path).unwrap()).unwrap();
    assert_eq!(content["unrelated"]["theme"], "amber");
    // The host editor retains the existing parent to preserve its formatting
    // and TOML comments. Only the owned registration is removal authority.
    assert_eq!(content["mcpServers"], json!({}));
    assert!(content["mcpServers"].get("agent-session-grep").is_none());
    remove_owned_registration(locator, &expected, Instant::now() + Duration::from_secs(5)).unwrap();
}
#[test]
fn remove_owned_registration_refuses_wrong_catalog_and_independent_node_edits() {
    let fixture = Fixture::new(vec![Host::Codex]);
    fixture.write(Host::Codex, "# independent comment\ntheme = 'amber'\n");
    let report = fixture.run();
    let locator = &report.private_receipts[0];
    let mut expected = McpRegistration::new(
        fixture.request.launcher.to_str().unwrap().into(),
        vec![
            "--db".into(),
            fixture.request.catalog.to_str().unwrap().into(),
            "mcp".into(),
        ],
    )
    .unwrap();
    let before = fs::read(&locator.config_path).unwrap();
    expected.args[1] = fixture
        .root
        .join("different-catalog.db")
        .to_str()
        .unwrap()
        .into();
    assert_eq!(
        remove_owned_registration(locator, &expected, Instant::now() + Duration::from_secs(5))
            .unwrap_err()
            .code,
        crate::host_config::ErrorCode::Unowned
    );
    assert_eq!(fs::read(&locator.config_path).unwrap(), before);
    expected.args[1] = fixture.request.catalog.to_str().unwrap().into();
    let mut document = String::from_utf8(before)
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    document["mcp_servers"]["agent-session-grep"]["args"] =
        toml_edit::value(toml_edit::Array::from_iter(["--db", "different", "mcp"]));
    fs::write(&locator.config_path, document.to_string()).unwrap();
    let edited = fs::read(&locator.config_path).unwrap();
    assert_eq!(
        remove_owned_registration(locator, &expected, Instant::now() + Duration::from_secs(5))
            .unwrap_err()
            .code,
        crate::host_config::ErrorCode::Conflict
    );
    assert_eq!(fs::read(&locator.config_path).unwrap(), edited);
    assert!(
        String::from_utf8(edited)
            .unwrap()
            .contains("# independent comment")
    );
}

#[test]
fn m2_profile_paths_defaults_and_overrides_use_distinct_host_namespaces() {
    let f = Fixture::new(vec![Host::WorkBuddy]);
    let p = f.request.profiles.as_ref().unwrap();
    for (host, suffix) in [
        (Host::ZCode, ".zcode/cli/config.json"),
        (Host::WorkBuddy, ".workbuddy/mcp.json"),
        (Host::Antigravity, ".gemini/config/mcp_config.json"),
        (Host::DeepSeekHarness, ".dsh/cordis.patch.yml"),
    ] {
        assert_eq!(config_path(host, p).unwrap(), p.home.join(suffix));
    }
    let profiles = ProfileRoots {
        home: f.root.join("ignored-home"),
        zcode_config_root: Some(f.root.join("zcode override 中文")),
        workbuddy_config_root: Some(f.root.join("workbuddy override")),
        antigravity_config_root: Some(f.root.join("antigravity override")),
        dsh_home: Some(f.root.join("dsh override")),
        ..ProfileRoots::default()
    };
    for (host, path) in [
        (
            Host::ZCode,
            f.root.join("zcode override 中文/cli/config.json"),
        ),
        (Host::WorkBuddy, f.root.join("workbuddy override/mcp.json")),
        (
            Host::Antigravity,
            f.root.join("antigravity override/mcp_config.json"),
        ),
        (
            Host::DeepSeekHarness,
            f.root.join("dsh override/cordis.patch.yml"),
        ),
    ] {
        assert_eq!(config_path(host, &profiles).unwrap(), path);
    }
    let mut profiles = profiles;
    profiles.workbuddy_config_root = Some("relative".into());
    assert_eq!(
        config_path(Host::WorkBuddy, &profiles).unwrap_err().code,
        SetupHostsErrorCode::InvalidPath
    );
    // An unrelated host's invalid override cannot change this selected target.
    assert!(config_path(Host::ZCode, &profiles).is_ok());
    assert!(!f.root.join("ignored-home").exists());
}

fn m2_setup_hosts() -> Vec<Host> {
    vec![
        Host::ClaudeCode,
        Host::Codex,
        Host::ZCode,
        Host::WorkBuddy,
        Host::Antigravity,
        Host::DeepSeekHarness,
    ]
}
fn m2_config_node(host: Host, bytes: &[u8]) -> Value {
    if host == Host::DeepSeekHarness {
        let docs =
            yaml_rust2::YamlLoader::load_from_str(std::str::from_utf8(bytes).unwrap()).unwrap();
        let row = &docs[0][0]["insert"][0];
        return json!({"command":row["config"]["command"].as_str().unwrap(),
            "args":row["config"]["args"].as_vec().unwrap().iter().map(|s| s.as_str().unwrap()).collect::<Vec<_>>(),
            "serverName":row["config"]["serverName"].as_str().unwrap(),
            "name":row["name"].as_str().unwrap()});
    }
    let value: Value = if host == Host::Codex {
        toml_edit::de::from_str(std::str::from_utf8(bytes).unwrap()).unwrap()
    } else {
        serde_json::from_slice(bytes).unwrap()
    };
    match host {
        Host::ZCode => value["mcp"]["servers"]["agent-session-grep"].clone(),
        Host::Codex => value["mcp_servers"]["agent-session-grep"].clone(),
        _ => value["mcpServers"]["agent-session-grep"].clone(),
    }
}

#[test]
fn m2_all_six_local_config_transactions_repeat_and_remove_with_private_receipt_chain() {
    let f = Fixture::new(m2_setup_hosts());
    f.write(
        Host::ZCode,
        r#"{"plugins":{"kept":true},"mcp":{"timeoutMs":123}}"#,
    );
    f.write(
        Host::WorkBuddy,
        r#"{"mcpServers":{"other":{"command":"other"}}}"#,
    );
    f.write(
        Host::Antigravity,
        r#"{"mcpServers":{"other":{"disabled":true}}}"#,
    );
    f.write(Host::DeepSeekHarness, "# user profile\n");
    let first = f.run();
    assert_eq!(first.hosts.len(), 6);
    assert_eq!(first.private_receipts.len(), 6);
    for summary in &first.hosts {
        assert_eq!(summary.configuration, ConfigurationStage::Configured);
        assert!(summary.owned_by_asg);
        assert_eq!(summary.host_handshake, HostHandshakeStage::Pending);
        let node = m2_config_node(summary.host, &fs::read(f.path(summary.host)).unwrap());
        assert_eq!(node["command"], f.request.launcher.to_str().unwrap());
        assert_eq!(
            node["args"],
            json!(["--db", f.request.catalog.to_str().unwrap(), "mcp"])
        );
        if summary.host == Host::DeepSeekHarness {
            assert_eq!(node["serverName"], "agent-session-grep");
            assert_eq!(node["name"], "@deepseek-ai/dsh-mcp-client");
        }
    }
    let second = f.run();
    assert!(
        second
            .hosts
            .iter()
            .all(|h| h.configuration == ConfigurationStage::Unchanged && h.owned_by_asg)
    );
    let public =
        serde_json::to_string(&json!({"hosts":second.hosts,"local_asg":second.local_asg})).unwrap();
    for private in [
        f.root.to_str().unwrap(),
        "transaction_id",
        "command",
        "PRIVATE_SETTING",
    ] {
        assert!(!public.contains(private));
    }
    let expected = McpRegistration::new(
        f.request.launcher.to_str().unwrap().into(),
        vec![
            "--db".into(),
            f.request.catalog.to_str().unwrap().into(),
            "mcp".into(),
        ],
    )
    .unwrap();
    for locator in &second.private_receipts {
        let removed =
            remove_owned_registration(locator, &expected, Instant::now() + Duration::from_secs(5))
                .unwrap();
        assert_eq!(removed.status, crate::host_config::EditStatus::Removed);
        assert_eq!(
            remove_owned_registration(locator, &expected, Instant::now() + Duration::from_secs(5))
                .unwrap()
                .status,
            crate::host_config::EditStatus::Unchanged
        );
    }
    let zcode: Value = serde_json::from_slice(&fs::read(f.path(Host::ZCode)).unwrap()).unwrap();
    assert_eq!(zcode["plugins"]["kept"], true);
    assert_eq!(zcode["mcp"]["timeoutMs"], 123);
    assert!(!f.root.join("profile/.codebuddy").exists());
    assert!(!f.root.join("profile/.agents").exists());
}

#[test]
fn m2_only_selected_host_and_duplicate_choices_never_adopt_other_namespaces() {
    for host in [
        Host::ZCode,
        Host::WorkBuddy,
        Host::Antigravity,
        Host::DeepSeekHarness,
    ] {
        let f = Fixture::new(vec![host]);
        let report = f.run();
        assert_eq!(report.hosts.len(), 1);
        assert_eq!(report.hosts[0].host, host);
        for other in m2_setup_hosts().into_iter().filter(|h| *h != host) {
            assert!(!f.path(other).exists());
        }
    }
    let f = Fixture::new(vec![Host::ZCode, Host::WorkBuddy, Host::ZCode]);
    assert_eq!(
        setup_selected_hosts(&f.request).err().unwrap().code,
        SetupHostsErrorCode::InvalidSelection
    );
    assert!(!f.root.join("profile").exists());
}

#[test]
fn m2_cordis_unsupported_style_is_partial_and_does_not_block_json_hosts() {
    let f = Fixture::new(vec![
        Host::DeepSeekHarness,
        Host::ZCode,
        Host::WorkBuddy,
        Host::Antigravity,
    ]);
    let original = "[{ insert: [] }]\n";
    f.write(Host::DeepSeekHarness, original);
    let report = f.run();
    assert_eq!(
        report.hosts[0].configuration,
        ConfigurationStage::Unsupported
    );
    assert!(!report.hosts[0].owned_by_asg);
    assert!(
        report.hosts[1..]
            .iter()
            .all(|h| h.configuration == ConfigurationStage::Configured)
    );
    assert_eq!(
        fs::read_to_string(f.path(Host::DeepSeekHarness)).unwrap(),
        original
    );
    assert_eq!(report.private_receipts.len(), 3);
}

#[test]
fn m2_environment_looks_up_only_selected_config_override_and_never_mutates_env() {
    let home = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let base = Fixture::new(vec![Host::WorkBuddy]);
    for (host, variable, suffix) in [
        (Host::ZCode, "ASG_ZCODE_CONFIG_ROOT", "cli/config.json"),
        (Host::WorkBuddy, "ASG_WORKBUDDY_CONFIG_ROOT", "mcp.json"),
        (
            Host::Antigravity,
            "ASG_ANTIGRAVITY_CONFIG_ROOT",
            "mcp_config.json",
        ),
        (Host::DeepSeekHarness, "DSH_HOME", "cordis.patch.yml"),
    ] {
        let target = base.root.join(format!("{} isolated override", host.id()));
        let mut seen = Vec::new();
        let profiles = profiles_from_environment(&[host], |name| {
            seen.push(name.to_owned());
            if name == home {
                return Some(base.root.join("ignored-home").into_os_string());
            }
            if name == variable {
                return Some(target.clone().into_os_string());
            }
            panic!("unselected environment lookup");
        })
        .unwrap();
        assert_eq!(seen, vec![home, variable]);
        assert_eq!(config_path(host, &profiles).unwrap(), target.join(suffix));
        let error = profiles_from_environment(&[host], |name| {
            if name == home {
                Some(base.root.clone().into_os_string())
            } else if name == variable {
                Some(std::ffi::OsString::new())
            } else {
                panic!("unselected environment lookup");
            }
        })
        .err()
        .unwrap();
        assert_eq!(error.code, SetupHostsErrorCode::InvalidPath);
    }
    assert!(!base.root.join("ignored-home").exists());
}

#[test]
fn m2_zcode_fallback_is_preserved_unowned_without_modifying_generic_profile() {
    let f = Fixture::new(vec![Host::ZCode, Host::WorkBuddy]);
    let generic = f
        .request
        .profiles
        .as_ref()
        .unwrap()
        .home
        .join(".agents/mcp.json");
    fs::create_dir_all(generic.parent().unwrap()).unwrap();
    let bytes = br#"{"mcpServers":{"unowned":{"command":"other"}}}"#;
    fs::write(&generic, bytes).unwrap();
    let report = f.run();
    assert_eq!(
        report.hosts[0].configuration,
        ConfigurationStage::Configured
    );
    assert!(report.hosts[0].owned_by_asg);
    let native: Value = serde_json::from_slice(&fs::read(f.path(Host::ZCode)).unwrap()).unwrap();
    assert_eq!(native["mcp"]["servers"]["unowned"]["command"], "other");
    assert!(native["mcp"]["servers"]["agent-session-grep"].is_object());
    assert_eq!(fs::read(&generic).unwrap(), bytes);
    assert_eq!(
        report.hosts[1].configuration,
        ConfigurationStage::Configured
    );
}
