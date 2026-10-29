use super::*;
use agent_session_grep_adapters_sqlite::SCHEMA_VERSION;
use agent_session_grep_ports::control::BackgroundControl;

// Schema 20 is an explicit historical candidate, never the current fixture.
const HISTORICAL_CATALOG_SCHEMA: u32 = 20;
fn current_catalog_schema() -> u32 {
    u32::try_from(SCHEMA_VERSION).expect("current adapter schema must fit release metadata")
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}
#[test]
fn update_options_are_explicit_and_never_infer_apply() {
    assert!(parse(&args(&["update"])).is_err());
    assert!(parse(&args(&["update", "apply"])).is_err());
    assert!(parse(&args(&["update", "check", "--from", "a.zip"])).is_err());
    assert!(matches!(
        parse(&args(&["update", "check", "--channel", "beta"]))
            .unwrap()
            .channel,
        Some(Channel::Beta)
    ));
}
#[test]
fn offline_bundle_requires_known_archive_and_sibling_metadata() {
    let Action::Apply {
        archive,
        manifest,
        sums,
    } = parse(&args(&["update", "apply", "--from", "bundle.tar.gz"]))
        .unwrap()
        .action
    else {
        panic!()
    };
    assert_eq!(archive, Path::new("bundle.tar.gz"));
    assert_eq!(manifest, Path::new("bundle.manifest.json"));
    assert_eq!(sums, Path::new("SHA256SUMS"));
    assert!(parse(&args(&["update", "apply", "--from", "bundle.exe"])).is_err());
}
#[test]
fn repeat_or_unknown_switches_are_not_silent() {
    assert!(
        parse(&args(&[
            "update",
            "check",
            "--channel",
            "beta",
            "--channel",
            "stable"
        ]))
        .is_err()
    );
    assert!(parse(&args(&["update", "recover", "--channel", "beta"])).is_err());
    assert!(
        parse(&args(&[
            "update",
            "apply",
            "--from",
            "a.zip",
            "--allow-downgrade",
            "true"
        ]))
        .is_err()
    );
}
#[test]
fn update_status_is_content_free_and_honest() {
    let identity = VersionIdentity {
        version: "0.2.0-beta.1".into(),
        target: agent_session_grep_launcher::metadata::BUILD_TARGET.into(),
        source_commit: "a".repeat(40),
        relative_dir: format!("versions/0.2.0-beta.1-{}", &"b".repeat(64)[..12]),
        app_sha256: "b".repeat(64),
        catalog_schema: current_catalog_schema(),
        control_schema: 1,
        launcher_protocol: 1,
    };
    let state = State::new(UpdateStart {
        update_id: ControlId::parse("update").unwrap(),
        owner: ControlId::parse("owner").unwrap(),
        old: identity.clone(),
        new: identity,
        archive_sha256: "c".repeat(64),
        manifest_sha256: "d".repeat(64),
        old_pointer_generation: 1,
        stable_launcher_sha256: "e".repeat(64),
        catalog: PathBuf::from(if cfg!(windows) {
            "C:/private/catalog.db"
        } else {
            "/private/catalog.db"
        }),
        checkpoint: Checkpoint {
            installation_id: "install".into(),
            policy_epoch: 0,
            control_seq: 0,
            desired_updates: "paused".into(),
            catalog_incarnation: "catalog".into(),
            catalog_generation: 0,
            catalog_schema: current_catalog_schema(),
        },
    })
    .unwrap();
    let data = state_report(&state);
    let text = data.to_string();
    assert!(!text.contains("/private"));
    assert!(!text.contains("catalog.db"));
    assert_eq!(data["freshness"], "unknown");
    assert_eq!(data["recovery_required"], true);
}

fn build_identity() -> VersionIdentity {
    VersionIdentity {
        version: "0.2.0-beta.1".into(),
        target: agent_session_grep_launcher::metadata::BUILD_TARGET.into(),
        source_commit: "a".repeat(40),
        relative_dir: format!("versions/0.2.0-beta.1-{}", "b".repeat(12)),
        app_sha256: "b".repeat(64),
        catalog_schema: current_catalog_schema(),
        control_schema: u32::try_from(
            agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION,
        )
        .expect("current control schema must fit release metadata"),
        launcher_protocol: 1,
    }
}

#[test]
fn recorded_restart_failure_recovery_rolls_back_instead_of_repeating_forward() {
    let identity = build_identity();
    let mut state = State::new(UpdateStart {
        update_id: ControlId::parse("update").unwrap(),
        owner: ControlId::parse("owner").unwrap(),
        old: identity.clone(),
        new: identity,
        archive_sha256: "c".repeat(64),
        manifest_sha256: "d".repeat(64),
        old_pointer_generation: 1,
        stable_launcher_sha256: "e".repeat(64),
        catalog: std::env::temp_dir().join("catalog.db"),
        checkpoint: Checkpoint {
            installation_id: "install".into(),
            policy_epoch: 0,
            control_seq: 0,
            desired_updates: "running".into(),
            catalog_incarnation: "catalog".into(),
            catalog_generation: 1,
            catalog_schema: current_catalog_schema(),
        },
    })
    .unwrap();
    state.phase = Phase::SelfChecked;
    state.self_checked = true;
    state.error_code = Some("restart_failed".into());
    assert!(!recovery_can_finish_active_update(&state));

    state.error_code = None;
    assert!(recovery_can_finish_active_update(&state));
    state.phase = Phase::Switched;
    assert!(recovery_can_finish_active_update(&state));
    state.phase = Phase::Staged;
    assert!(!recovery_can_finish_active_update(&state));
}

fn build_capture(success: bool) -> crate::setup_hosts::LocalCapture {
    let expected = build_identity();
    crate::setup_hosts::LocalCapture {
        success,
        stdout: serde_json::to_vec(&json!({
            "schema": "asg.build-info/v1", "product": "agent-session-grep",
            "version": expected.version, "target": expected.target,
            "catalog_schema": expected.catalog_schema,
            "control_schema": expected.control_schema, "launcher_protocol": 1
        }))
        .unwrap(),
        stderr: Vec::new(),
    }
}
#[test]
fn candidate_output_cannot_hide_failed_process_exit() {
    let expected = build_identity();
    assert!(validate_candidate_info(&build_capture(true), &expected).is_ok());
    let error = validate_candidate_info(&build_capture(false), &expected).unwrap_err();
    assert_eq!(error.0.code, CanonicalCode::SchemaIncompatible);
    let mut output = build_capture(true);
    output.stderr = b"private probe diagnostic".to_vec();
    assert!(validate_candidate_info(&output, &expected).is_err());
    output.stderr.clear();
    let mut wrong = expected;
    wrong.control_schema += 1;
    assert!(validate_candidate_info(&output, &wrong).is_err());
}
#[test]
fn historical_candidate_schema_must_match_its_verified_metadata_and_active_identity() {
    let current = build_identity();
    let current_output = build_capture(true);
    let mut historical = current.clone();
    historical.catalog_schema = HISTORICAL_CATALOG_SCHEMA;
    let mut historical_output = build_capture(true);
    let mut value: Value = serde_json::from_slice(&historical_output.stdout).unwrap();
    value["catalog_schema"] = HISTORICAL_CATALOG_SCHEMA.into();
    historical_output.stdout = serde_json::to_vec(&value).unwrap();
    assert!(validate_candidate_info(&current_output, &current).is_ok());
    assert!(validate_candidate_info(&historical_output, &historical).is_ok());
    for (output, expected) in [
        (&historical_output, &current),
        (&current_output, &historical),
    ] {
        assert_eq!(
            validate_candidate_info(output, expected)
                .unwrap_err()
                .0
                .code,
            CanonicalCode::SchemaIncompatible
        );
    }
    assert!(active_identity_matches(&historical, 7, &historical, 7));
    assert!(!active_identity_matches(&historical, 7, &current, 7));
    assert!(!active_identity_matches(&current, 7, &historical, 7));
}
#[test]
fn pointer_generation_is_part_of_active_update_verification() {
    let expected = build_identity();
    assert!(active_identity_matches(&expected, 7, &expected, 7));
    assert!(!active_identity_matches(&expected, 6, &expected, 7));
    let mut different = expected.clone();
    different.app_sha256 = "c".repeat(64);
    assert!(!active_identity_matches(&different, 7, &expected, 7));
}
#[test]
fn metadata_check_timeout_does_not_claim_an_existing_update_journal() {
    let error = check_error(update_check::UpdateCheckError::new(
        UpdateCheckErrorCode::Timeout,
    ));
    assert_eq!(error.0.code, CanonicalCode::SourceIo);
    assert!(!error.0.message.contains("recover"));
}

#[test]
fn post_drain_checkpoint_uses_latest_catalog_and_current_pause() {
    use agent_session_grep_adapters_sqlite::{
        SqliteControlStore, managed_maintenance::CatalogIdentity,
    };
    use agent_session_grep_ports::control::{ControlStore, DesiredUpdates};
    let tmp = agent_session_grep_testkit::tempdir().unwrap();
    let control = crate::retry_fixture_busy(|| {
        SqliteControlStore::create(
            &tmp.path().join("control"),
            &ControlId::parse("install").unwrap(),
            DesiredUpdates::Running,
        )
    });
    let before = control.status().unwrap();
    let initial = Checkpoint {
        installation_id: "install".into(),
        policy_epoch: before.policy.policy_epoch.get() as u64,
        control_seq: before.policy.control_seq.get() as u64,
        desired_updates: "running".into(),
        catalog_incarnation: "catalog".into(),
        catalog_generation: 2,
        catalog_schema: current_catalog_schema(),
    };
    control
        .set_desired_updates(before.policy.control_seq, DesiredUpdates::Paused)
        .unwrap();
    let mut catalog = CatalogIdentity {
        installation: ControlId::parse("install").unwrap(),
        incarnation: ControlId::parse("catalog").unwrap(),
        schema: initial.catalog_schema,
        generation: 3,
    };
    let current = control.status().unwrap();
    let actual = quiesced_checkpoint(&current, &catalog, &initial).unwrap();
    assert_eq!(actual.catalog_generation, 3);
    assert_eq!(actual.desired_updates, "paused");
    assert_eq!(initial.catalog_generation, 2);
    assert!(actual.control_seq > initial.control_seq);
    catalog.incarnation = ControlId::parse("other_catalog").unwrap();
    assert!(quiesced_checkpoint(&current, &catalog, &initial).is_err());
    catalog.incarnation = ControlId::parse("catalog").unwrap();
    catalog.generation = 1;
    assert!(quiesced_checkpoint(&current, &catalog, &initial).is_err());
    catalog.generation = 3;
    catalog.installation = ControlId::parse("other_install").unwrap();
    assert!(quiesced_checkpoint(&current, &catalog, &initial).is_err());
}

#[test]
fn failed_native_candidate_probe_is_rejected_after_actual_execution() {
    use std::{fs, process::Command};
    let tmp = agent_session_grep_testkit::tempdir().unwrap();
    let source = tmp.path().join("candidate.rs");
    let executable = tmp.path().join(if cfg!(windows) {
        "candidate.exe"
    } else {
        "candidate"
    });
    let output = String::from_utf8(build_capture(true).stdout).unwrap();
    fs::write(
        &source,
        format!(
            "fn main() {{ println!(\"{{}}\", {:?}); std::process::exit(3); }}",
            output
        ),
    )
    .unwrap();
    let compile = Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "synthetic candidate did not compile"
    );
    assert_eq!(
        candidate_info(
            &executable,
            &build_identity(),
            Instant::now() + Duration::from_secs(5)
        )
        .unwrap_err()
        .0
        .code,
        CanonicalCode::SchemaIncompatible
    );
}
#[test]
fn update_drain_requires_real_supervisor_and_worker_locks() {
    use agent_session_grep_adapters_sqlite::managed_locks::{ExclusiveGuard, LockKind};
    let tmp = agent_session_grep_testkit::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    // The process registry is nonblocking even for distinct roots. Establish
    // fixture ownership within its original finite setup budget, then measure
    // the actual held-lock refusal using the unchanged 40ms drain deadline.
    let acquire = |kind: LockKind| {
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            match ExclusiveGuard::try_acquire(&root, kind.clone()) {
                Ok(guard) => break guard,
                Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("synthetic fixture ownership failed: {error:?}"),
            }
        }
    };
    let supervisor = acquire(LockKind::Supervisor);
    let deadline = Instant::now() + Duration::from_millis(40);
    assert!(drain_background_lifetime(&root, deadline).is_err());
    drop(supervisor);
    let worker = acquire(LockKind::Background);
    let deadline = Instant::now() + Duration::from_millis(40);
    assert!(drain_background_lifetime(&root, deadline).is_err());
    drop(worker);
    let (supervisor, worker) =
        drain_background_lifetime(&root, Instant::now() + Duration::from_secs(1)).unwrap();
    assert!(ExclusiveGuard::try_acquire(&root, LockKind::Supervisor).is_err());
    assert!(ExclusiveGuard::try_acquire(&root, LockKind::Background).is_err());
    drop(worker);
    drop(supervisor);
    drop(acquire(LockKind::Supervisor));
}
#[test]
fn private_native_binding_is_hash_confirmed_and_never_leaks_in_report() {
    use sha2::{Digest, Sha256};
    use std::fs;
    let tmp = agent_session_grep_testkit::tempdir().unwrap();
    let prefix = tmp.path().join("install");
    fs::create_dir(&prefix).unwrap();
    let identity = build_identity();
    let state = State::new(UpdateStart {
        update_id: ControlId::parse("update").unwrap(),
        owner: ControlId::parse("owner").unwrap(),
        old: identity.clone(),
        new: identity,
        archive_sha256: "c".repeat(64),
        manifest_sha256: "d".repeat(64),
        old_pointer_generation: 1,
        stable_launcher_sha256: "e".repeat(64),
        catalog: tmp.path().join("data/catalog.db"),
        checkpoint: Checkpoint {
            installation_id: "install".into(),
            policy_epoch: 0,
            control_seq: 0,
            desired_updates: "paused".into(),
            catalog_incarnation: "catalog".into(),
            catalog_generation: 0,
            catalog_schema: current_catalog_schema(),
        },
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let lock = update_state::acquire_installation_lock(&prefix, deadline).unwrap();
    let mut journal = Journal::create(&prefix, &lock, state, deadline).unwrap();
    assert!(read_native_binding(&journal).unwrap().is_none());
    let binding = NativeBinding {
        schema: "asg.update-native-binding/v1".into(),
        update_id: "update".into(),
        installation_id: "install".into(),
        location: crate::native_autostart::NativeLocation::WindowsRun {
            subkey: "synthetic\\registry".into(),
        },
        journal_root: tmp.path().join("data/native-autostart"),
        original_receipt: crate::native_autostart::AutostartReceipt {
            schema: "asg.native-autostart-receipt/v1".into(),
            installation_id: "install".into(),
            transaction_id: "f".repeat(32),
            kind: crate::native_autostart::NativeKind::WindowsRun,
            entry: "synthetic-owned-entry".into(),
            state: crate::native_autostart::ConfigurationState::Present,
            owned: true,
            before_sha256: None,
            configuration_sha256: Some("a".repeat(64)),
            displaced_preserved: false,
            directory_sync_supported: false,
        },
        old_supervisor_sha256: "a".repeat(64),
        new_supervisor_sha256: "b".repeat(64),
    };
    let bytes = serde_json::to_vec(&binding).unwrap();
    update_state::write_new(&journal.run_root().join(NATIVE_BINDING_FILE), &bytes).unwrap();
    assert!(read_native_binding(&journal).is_err());
    journal.state.native_binding_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
    journal.save(deadline).unwrap();
    assert_eq!(
        read_native_binding(&journal).unwrap().unwrap().update_id,
        "update"
    );
    let text = state_report(&journal.state).to_string();
    assert!(!text.contains("synthetic-owned-entry"));
    assert!(!text.contains("native-autostart"));
    fs::write(
        journal.run_root().join(NATIVE_BINDING_FILE),
        b"independent changed binding",
    )
    .unwrap();
    assert!(read_native_binding(&journal).is_err());
}

#[test]
fn schema_update_gate_admits_only_current_same_schema_program_pairs() {
    let current = build_identity();
    assert!(schema_update_supported(&current, &current));
    let mut next_version = current.clone();
    next_version.version = "0.2.0-beta.2".into();
    assert!(schema_update_supported(&current, &next_version));

    // An internal exact21 restore does not provide an old21 executor handoff.
    let mut historical = current.clone();
    historical.catalog_schema = 21;
    assert!(!schema_update_supported(&historical, &current));
    assert!(!schema_update_supported(&current, &historical));
    assert!(!schema_update_supported(&historical, &historical));
    for unsupported in [0, 19, 20, current.catalog_schema + 1] {
        let mut other = current.clone();
        other.catalog_schema = unsupported;
        assert!(!schema_update_supported(&other, &current));
        assert!(!schema_update_supported(&current, &other));
        assert!(!schema_update_supported(&other, &other));
    }
    for unsupported in [0, 1, current.control_schema + 1] {
        let mut other = current.clone();
        other.control_schema = unsupported;
        assert!(!schema_update_supported(&other, &current));
        assert!(!schema_update_supported(&current, &other));
        assert!(!schema_update_supported(&other, &other));
    }
}
#[test]
fn schema_rollback_never_pairs_current_catalog_with_the_old_program() {
    use agent_session_grep_adapters_sqlite::managed_maintenance::CatalogIdentity;
    let mut old = build_identity();
    old.catalog_schema = 21;
    let checkpoint = Checkpoint {
        installation_id: "install".into(),
        policy_epoch: 2,
        control_seq: 5,
        desired_updates: "paused".into(),
        catalog_incarnation: "catalog".into(),
        catalog_generation: 3,
        catalog_schema: 21,
    };
    let mut catalog = CatalogIdentity {
        installation: ControlId::parse("install").unwrap(),
        incarnation: ControlId::parse("recovered").unwrap(),
        schema: 22,
        generation: 3,
    };
    assert!(!recovered_catalog_matches_program(
        &catalog,
        &old,
        &checkpoint
    ));
    catalog.schema = 21;
    assert!(recovered_catalog_matches_program(
        &catalog,
        &old,
        &checkpoint
    ));
    catalog.generation = 2;
    assert!(!recovered_catalog_matches_program(
        &catalog,
        &old,
        &checkpoint
    ));
    catalog.generation = 3;
    catalog.installation = ControlId::parse("other").unwrap();
    assert!(!recovered_catalog_matches_program(
        &catalog,
        &old,
        &checkpoint
    ));
}

#[test]
fn update_control_scope_refuses_expired_work_and_restores_nested_original_end() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let control = crate::retry_fixture_busy(|| {
        SqliteControlStore::create(
            &temp.path().join("private"),
            &ControlId::parse("install").unwrap(),
            DesiredUpdates::Paused,
        )
    });
    let before = control.status().unwrap();
    let mut ran = false;
    let expired = with_update_deadline(&control, Instant::now() - Duration::from_millis(1), || {
        ran = true;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(expired.0.code, CanonicalCode::WriterBusy);
    assert!(!ran);
    let outer = Instant::now() + Duration::from_secs(1);
    with_update_deadline(&control, outer, || {
        let mut nested_ran = false;
        let nested =
            with_update_deadline(&control, Instant::now() - Duration::from_millis(1), || {
                nested_ran = true;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(nested.0.code, CanonicalCode::WriterBusy);
        assert!(!nested_ran);
        assert_eq!(control.status().unwrap(), before);
        Ok(())
    })
    .unwrap();
    assert_eq!(control.status().unwrap(), before);
}

#[test]
fn update_control_sql_contention_does_not_start_a_fresh_default_wait() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    let control = crate::retry_fixture_busy(|| {
        SqliteControlStore::create(
            &root,
            &ControlId::parse("install").unwrap(),
            DesiredUpdates::Paused,
        )
    });
    let before = control.status().unwrap();
    let contender = rusqlite::Connection::open(SqliteControlStore::path(&root)).unwrap();
    contender.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    let error = with_update_deadline(&control, started + Duration::from_millis(20), || {
        control
            .set_desired_updates(before.policy.control_seq, DesiredUpdates::Running)
            .map_err(port)?;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.0.code, CanonicalCode::WriterBusy);
    assert!(started.elapsed() < Duration::from_millis(200));
    contender.execute_batch("ROLLBACK").unwrap();
    with_update_deadline(&control, Instant::now() + Duration::from_secs(1), || {
        assert_eq!(control.status().unwrap(), before);
        control
            .set_desired_updates(before.policy.control_seq, DesiredUpdates::Running)
            .map_err(port)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        control.status().unwrap().desired_updates,
        DesiredUpdates::Running
    );
}

#[test]
fn completion_checks_the_catalog_under_its_owned_fence_before_clear() {
    use agent_session_grep_adapters_sqlite::{
        managed_locks::{ExclusiveGuard, JobLockKey, LockKind},
        managed_maintenance::inspect_catalog_identity,
        managed_store::ManagedStore,
    };
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    let prefix = temp.path().join("installation");
    std::fs::create_dir(&prefix).unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    let control = crate::retry_fixture_busy(|| {
        SqliteControlStore::create(
            &root,
            &ControlId::parse("install").unwrap(),
            DesiredUpdates::Paused,
        )
    });
    let db = root.join("catalog.db");
    let store =
        ManagedStore::create(&db, &control, ControlId::parse("catalog").unwrap(), 1).unwrap();
    {
        let worker_lock =
            crate::retry_fixture_busy(|| ExclusiveGuard::try_acquire(&root, LockKind::Background));
        let worker = control
            .bind_worker(&worker_lock, ControlId::parse("boot").unwrap())
            .unwrap();
        control
            .register_worker(control.status().unwrap().policy.control_seq, &worker, 1, 1)
            .unwrap();
        store.reconcile_progress(&control, &worker).unwrap();
    }
    drop(store);
    let lock = crate::retry_fixture_busy(|| {
        ExclusiveGuard::try_acquire(
            &prefix,
            LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
        )
    });
    {
        let guard = control_lock(&root, end).unwrap();
        let bound = control.bind_control_root(&guard).unwrap();
        control
            .record_verified_installation_prefix(&prefix, &lock, &bound, end)
            .unwrap();
    }
    let installation = control.bind_installation(&prefix, &lock).unwrap();
    let owner = ControlId::parse("owner").unwrap();
    let expected = build_identity();
    let initial = inspect_catalog_identity(&control, &db, end).unwrap();
    let status = control.status().unwrap();
    let checkpoint = Checkpoint {
        installation_id: initial.installation.as_str().to_owned(),
        policy_epoch: status.policy.policy_epoch.get() as u64,
        control_seq: status.policy.control_seq.get() as u64,
        desired_updates: "paused".into(),
        catalog_incarnation: initial.incarnation.as_str().to_owned(),
        catalog_generation: initial.generation,
        catalog_schema: initial.schema,
    };
    set_fence(
        &control,
        &installation,
        &owner,
        &root,
        MaintenancePhase::SelfChecked,
        false,
        end,
    )
    .unwrap();
    let fenced = control.status().unwrap();
    assert!(inspect_catalog_identity(&control, &db, end).is_err());
    verify_catalog_program_pair(
        &control,
        &installation,
        &owner,
        &db,
        &expected,
        &checkpoint,
        end,
    )
    .unwrap();
    assert_eq!(control.status().unwrap(), fenced);
    assert!(
        verify_catalog_program_pair(
            &control,
            &installation,
            &ControlId::parse("other").unwrap(),
            &db,
            &expected,
            &checkpoint,
            end,
        )
        .is_err()
    );
    let mut old = expected.clone();
    old.catalog_schema = 21;
    assert_eq!(
        verify_catalog_program_pair(&control, &installation, &owner, &db, &old, &checkpoint, end,)
            .unwrap_err()
            .0
            .code,
        CanonicalCode::UpdateRecoveryRequired
    );
    assert_eq!(control.status().unwrap(), fenced);
    clear_fence(&control, &installation, &owner, &root, end).unwrap();
    verify_catalog_program_pair(
        &control,
        &installation,
        &owner,
        &db,
        &expected,
        &checkpoint,
        end,
    )
    .unwrap();
    assert_eq!(
        control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
}
