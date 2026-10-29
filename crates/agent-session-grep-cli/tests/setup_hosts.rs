//! Actual ASG binary checks against disposable empty catalogs/profiles.
//! These tests do not run Claude/Codex or establish host acceptance.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore, SqliteStore, managed_store::ManagedStore,
};
use agent_session_grep_cli::{
    host_config::{Host, HostConfigStore},
    setup_hosts::{
        ConfigurationStage, ExpectedAsgIdentity, HostHandshakeStage, ProfileRoots,
        SetupHostsRequest, check_local_asg, setup_selected_hosts,
    },
};
use agent_session_grep_ports::control::{ControlId, ControlStore, DesiredUpdates};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn request() -> (tempfile::TempDir, SetupHostsRequest) {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let launcher = PathBuf::from(env!("CARGO_BIN_EXE_agent-session-grep"));
    let catalog = root.join("empty synthetic catalog.db");
    drop(SqliteStore::open_for_write(&catalog.to_string_lossy()).unwrap());
    let expected_identity = ExpectedAsgIdentity {
        version: env!("CARGO_PKG_VERSION").into(),
        launcher_sha256: format!("{:x}", Sha256::digest(fs::read(&launcher).unwrap())),
    };
    (
        temp,
        SetupHostsRequest {
            launcher,
            catalog,
            selected_hosts: vec![Host::ClaudeCode, Host::Codex],
            expected_identity,
            profiles: Some(ProfileRoots {
                home: root.join("isolated home"),
                claude_config_dir: None,
                codex_home: None,
                ..ProfileRoots::default()
            }),
            create_missing_parents: true,
        },
    )
}

#[test]
fn actual_local_app_initialize_and_config_stage_stay_separate_from_host_acceptance() {
    let (_temp, request) = request();
    let catalog_before = fs::read(&request.catalog).unwrap();
    let check = check_local_asg(
        &request.launcher,
        &request.catalog,
        &request.expected_identity,
    )
    .unwrap();
    assert!(check.version_verified && check.mcp_initialized);
    let first = setup_selected_hosts(&request).unwrap();
    assert_eq!(first.hosts.len(), 2);
    assert!(first.hosts.iter().all(|host| {
        host.configuration == ConfigurationStage::Configured
            && host.owned_by_asg
            && host.host_handshake == HostHandshakeStage::Pending
    }));
    let second = setup_selected_hosts(&request).unwrap();
    assert!(
        second.hosts.iter().all(|host| {
            host.configuration == ConfigurationStage::Unchanged && host.owned_by_asg
        })
    );
    for locator in second.private_receipts {
        let receipt = locator.read_receipt().unwrap();
        let store = HostConfigStore::open(
            &locator.config_path,
            &locator.transaction_root,
            locator.host,
        )
        .unwrap();
        store.remove(&receipt).unwrap();
    }
    assert_eq!(fs::read(&request.catalog).unwrap(), catalog_before);
}

#[test]
fn actual_app_missing_catalog_refuses_before_any_profile_write() {
    let (_temp, mut request) = request();
    request.catalog = request.catalog.with_file_name("absent.db");
    assert!(setup_selected_hosts(&request).is_err());
    assert!(!request.profiles.unwrap().home.exists());
    assert!(!request.catalog.exists());
}

#[test]
fn actual_managed_catalog_local_initialize_does_not_grant_host_acceptance() {
    let (_temp, mut request) = request();
    let root = request.catalog.parent().unwrap().join("managed");
    let control = SqliteControlStore::create(
        &root,
        &ControlId::parse("setup-host-fixture-installation").unwrap(),
        DesiredUpdates::Paused,
    )
    .unwrap();
    request.catalog = root.join("catalog.db");
    drop(
        ManagedStore::create(
            &request.catalog,
            &control,
            ControlId::parse("setup-host-fixture-catalog").unwrap(),
            1,
        )
        .unwrap(),
    );
    drop(control);
    let report = setup_selected_hosts(&request).unwrap();
    assert!(report.local_asg.mcp_initialized);
    assert!(
        report
            .hosts
            .iter()
            .all(|h| h.configuration == ConfigurationStage::Configured
                && h.host_handshake == HostHandshakeStage::Pending)
    );
}

#[cfg(windows)]
#[test]
fn actual_setup_coexists_with_live_managed_catalog_writer() {
    let (_temp, mut request) = request();
    let root = request.catalog.parent().unwrap().join("live-managed");
    let control = SqliteControlStore::create(
        &root,
        &ControlId::parse("setup-live-writer-installation").unwrap(),
        DesiredUpdates::Running,
    )
    .unwrap();
    request.catalog = root.join("catalog.db");
    drop(
        ManagedStore::create(
            &request.catalog,
            &control,
            ControlId::parse("setup-live-writer-catalog").unwrap(),
            1,
        )
        .unwrap(),
    );
    let _writer = ManagedStore::open_for_write(&request.catalog, &control).unwrap();

    let report = setup_selected_hosts(&request).unwrap();
    assert!(report.local_asg.version_verified && report.local_asg.mcp_initialized);
    assert_eq!(report.hosts.len(), 2);
    assert!(report.hosts.iter().all(|host| {
        host.configuration == ConfigurationStage::Configured
            && host.owned_by_asg
            && host.host_handshake == HostHandshakeStage::Pending
    }));
}

fn managed_fixture(root: &std::path::Path, installation: &str, incarnation: &str) -> PathBuf {
    let control = SqliteControlStore::create(
        root,
        &ControlId::parse(installation).unwrap(),
        DesiredUpdates::Paused,
    )
    .unwrap();
    let catalog = root.join("catalog.db");
    drop(
        ManagedStore::create(
            &catalog,
            &control,
            ControlId::parse(incarnation).unwrap(),
            1,
        )
        .unwrap(),
    );
    catalog
}

#[test]
fn replacement_at_real_probe_completion_never_mutates_replacement_or_profiles() {
    use agent_session_grep_cli::setup_hosts::{
        SetupHostsErrorCode, SetupIdentity, SetupStage, setup_selected_hosts_checked,
    };
    for same_logical_identity in [false, true] {
        let (temp, mut request) = request();
        let base = temp.path().canonicalize().unwrap();
        let selected = base.join("selected");
        let replacement = base.join("replacement");
        request.catalog = managed_fixture(&selected, "installation-a", "catalog-a");
        let replacement_catalog = managed_fixture(
            &replacement,
            if same_logical_identity {
                "installation-a"
            } else {
                "installation-b"
            },
            if same_logical_identity {
                "catalog-a"
            } else {
                "catalog-b"
            },
        );
        let identity = SetupIdentity::capture(&request.catalog).unwrap();
        let control_bytes = fs::read(SqliteControlStore::path(&replacement)).unwrap();
        let catalog_bytes = fs::read(replacement_catalog).unwrap();
        let mut swapped = false;
        let report = setup_selected_hosts_checked(&request, &mut |stage| {
            if stage == SetupStage::AfterProbe {
                // The actual version/MCP probes succeeded for A. Model the
                // replacement completing before that result is consumed.
                fs::rename(&selected, base.join("original")).unwrap();
                fs::rename(&replacement, &selected).unwrap();
                swapped = true;
            }
            identity
                .validate()
                .map_err(|_| SetupHostsErrorCode::IdentityMismatch.into())
        })
        .unwrap();
        assert!(swapped && report.local_asg.mcp_initialized);
        assert_eq!(
            report.interruption,
            Some(SetupHostsErrorCode::IdentityMismatch)
        );
        assert!(report.hosts.is_empty() && report.private_receipts.is_empty());
        assert!(!request.profiles.as_ref().unwrap().home.exists());
        assert_eq!(
            fs::read(SqliteControlStore::path(&selected)).unwrap(),
            control_bytes
        );
        assert_eq!(fs::read(&request.catalog).unwrap(), catalog_bytes);
        let current = SqliteControlStore::open_current_read_only(&selected).unwrap();
        assert!(!current.status().unwrap().autostart_enabled);
        assert!(
            SetupIdentity::capture(&request.catalog).is_ok(),
            "fresh setup may adopt B explicitly"
        );
    }
}

#[test]
fn replacement_before_each_later_stage_preserves_completed_host_work() {
    use agent_session_grep_cli::setup_hosts::{
        SetupHostsErrorCode, SetupIdentity, SetupStage, setup_selected_hosts_checked,
    };
    for target in [
        SetupStage::BeforeProfile,
        SetupStage::BeforeConfig,
        SetupStage::BeforeReceipt,
    ] {
        let (temp, mut request) = request();
        let base = temp.path().canonicalize().unwrap();
        let selected = base.join("selected");
        let replacement = base.join("replacement");
        request.catalog = managed_fixture(&selected, "installation-a", "catalog-a");
        managed_fixture(&replacement, "installation-b", "catalog-b");
        let identity = SetupIdentity::capture(&request.catalog).unwrap();
        let control_bytes = fs::read(SqliteControlStore::path(&replacement)).unwrap();
        let mut seen = 0;
        let report = setup_selected_hosts_checked(&request, &mut |stage| {
            if stage == target {
                seen += 1;
                if seen == 2 {
                    fs::rename(&selected, base.join("original")).unwrap();
                    fs::rename(&replacement, &selected).unwrap();
                }
            }
            identity
                .validate()
                .map_err(|_| SetupHostsErrorCode::IdentityMismatch.into())
        })
        .unwrap();
        assert_eq!(
            report.interruption,
            Some(SetupHostsErrorCode::IdentityMismatch)
        );
        assert_eq!(
            report.hosts[0].configuration,
            ConfigurationStage::Configured
        );
        assert!(report.private_receipts[0].read_receipt().is_ok());
        let home = &request.profiles.as_ref().unwrap().home;
        assert!(home.join(".claude.json").is_file());
        assert_eq!(
            home.join(".codex/config.toml").exists(),
            target == SetupStage::BeforeReceipt
        );
        assert_eq!(
            fs::read(SqliteControlStore::path(&selected)).unwrap(),
            control_bytes
        );
        if target == SetupStage::BeforeReceipt {
            assert_eq!(
                report.hosts[1].configuration,
                ConfigurationStage::RecoveryRequired
            );
            assert!(!report.private_receipts[1].receipt_path.exists());
        }
    }
}

#[test]
fn same_root_installation_or_catalog_replacement_invalidates_setup_identity() {
    use agent_session_grep_cli::setup_hosts::SetupIdentity;
    for replace_control in [true, false] {
        let (temp, _) = request();
        let base = temp.path().canonicalize().unwrap();
        let root = base.join("selected");
        let catalog = managed_fixture(&root, "installation-a", "catalog-a");
        let replacement = base.join("replacement");
        let other = managed_fixture(
            &replacement,
            if replace_control {
                "installation-b"
            } else {
                "installation-a"
            },
            "catalog-b",
        );
        let identity = SetupIdentity::capture(&catalog).unwrap();
        if replace_control {
            fs::rename(SqliteControlStore::path(&root), base.join("old-control.db")).unwrap();
            fs::rename(
                SqliteControlStore::path(&replacement),
                SqliteControlStore::path(&root),
            )
            .unwrap();
        }
        fs::rename(&catalog, base.join("old-catalog.db")).unwrap();
        fs::rename(other, &catalog).unwrap();
        let before = fs::read(SqliteControlStore::path(&root)).unwrap();
        assert!(identity.validate().is_err());
        assert_eq!(fs::read(SqliteControlStore::path(&root)).unwrap(), before);
    }
}
