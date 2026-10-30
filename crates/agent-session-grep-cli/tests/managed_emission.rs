//! Real CLI helper processes, synthetic policy roots, and controlled OS pipes.
//! Importing the module also exercises the parent's supervisor against the same
//! built executable; no second helper implementation or output thread is used.
#[path = "../src/managed_emit.rs"]
mod managed_emit;

use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, LockKind},
};
use agent_session_grep_ports::{
    PortError, SearchProvider,
    control::{
        CanonicalLocator, ControlId, ControlSeq, ControlStore, DesiredUpdates, PolicyEpoch,
        RootKind, ScopeRegion, SelectionRequest,
    },
};
use managed_emit::{
    EmissionFailureKind, EmissionOutcome, INTERNAL_COMMAND, INTERNAL_CONTROL_COMMAND,
    MAX_FRAME_BYTES,
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_agent-session-grep"))
}
fn id(s: &str) -> ControlId {
    ControlId::parse(s).unwrap()
}
fn setup() -> (tempfile::TempDir, PathBuf, SqliteControlStore) {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    let store = SqliteControlStore::create(
        &root,
        &id("synthetic_installation"),
        DesiredUpdates::Running,
    )
    .unwrap();
    (temp, root, store)
}
fn acquire(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => thread::yield_now(),
            Err(error) => panic!("guard unavailable: {error:?}"),
        }
    }
}
fn start_helper(packet: Vec<u8>) -> (Child, thread::JoinHandle<std::io::Result<()>>) {
    start_named_helper(INTERNAL_COMMAND, packet)
}
fn start_named_helper(
    name: &str,
    packet: Vec<u8>,
) -> (Child, thread::JoinHandle<std::io::Result<()>>) {
    let mut command = Command::new(binary());
    command
        .arg(name)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let feeder = thread::spawn(move || {
        input.write_all(&packet)?;
        drop(input);
        Ok(())
    });
    (child, feeder)
}
fn complete_helper(packet: Vec<u8>) -> std::process::Output {
    complete_named_helper(INTERNAL_COMMAND, packet)
}
fn complete_named_helper(name: &str, packet: Vec<u8>) -> std::process::Output {
    let (mut child, feeder) = start_named_helper(name, packet);
    let deadline = Instant::now() + Duration::from_secs(5);
    // This helper is only used for bounded small frames; tests with intentionally
    // full output pipes below explicitly supervise and terminate the child.
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("helper failed to finish");
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = feeder.join().unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn actual_helper_writes_exact_frame_and_normal_exit() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let frame = b"{\"synthetic\":\"evidence\"}\n";
    let packet =
        managed_emit::packet_for_test(&root, &policy.installation_id, policy.policy_epoch, frame);
    let output = complete_helper(packet);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, frame);
    assert_eq!(output.stderr, [1]); // fixed private handshake, no path/content
    drop(acquire(&root, LockKind::PolicyEmission));
}

#[test]
fn epoch_installation_and_physical_root_mismatch_emit_no_content() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let frame = b"MUST_NOT_APPEAR\n";
    for (installation, epoch) in [
        (policy.installation_id.clone(), PolicyEpoch::new(1).unwrap()),
        (id("wrong_installation"), policy.policy_epoch),
    ] {
        let output = complete_helper(managed_emit::packet_for_test(
            &root,
            &installation,
            epoch,
            frame,
        ));
        assert_eq!(output.status.code(), Some(7));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    let mut packet =
        managed_emit::packet_for_test(&root, &policy.installation_id, policy.policy_epoch, frame);
    packet[26] ^= 1;
    let output = complete_helper(packet);
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn malformed_oversized_and_extra_arguments_have_no_output() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let mut oversized =
        managed_emit::packet_for_test(&root, &policy.installation_id, policy.policy_epoch, b"x");
    oversized[14..18].copy_from_slice(&((MAX_FRAME_BYTES + 1) as u32).to_le_bytes());
    let mut trailing =
        managed_emit::packet_for_test(&root, &policy.installation_id, policy.policy_epoch, b"x");
    trailing.push(1);
    for packet in [b"invalid".to_vec(), oversized, trailing] {
        let output = complete_helper(packet);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    let output = Command::new(binary())
        .args([INTERNAL_COMMAND, "unexpected"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn paused_updates_still_emit_but_pending_revocation_does_not() {
    let (_temp, root, store) = setup();
    let source = root.join("synthetic.jsonl");
    std::fs::write(&source, b"synthetic").unwrap();
    let selected = store
        .add_selection(
            ControlSeq::new(0).unwrap(),
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Claude,
                    locator: CanonicalLocator::from_path(&source.canonicalize().unwrap()).unwrap(),
                    kind: RootKind::Exact,
                },
                root_identity: Some(id("synthetic_source_root")),
                now_ms: 1,
            },
        )
        .unwrap();
    store
        .set_desired_updates(selected.control_seq, DesiredUpdates::Paused)
        .unwrap();
    let policy = store.status().unwrap().policy;
    let output = complete_helper(managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        b"allowed while paused\n",
    ));
    assert!(output.status.success());
    assert_eq!(output.stdout, b"allowed while paused\n");
    store
        .revoke_selection(policy.control_seq, &selected.value.id, None, 2)
        .unwrap();
    let policy = store.status().unwrap().policy;
    let output = complete_helper(managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        b"denied\n",
    ));
    assert_eq!(output.status.code(), Some(10));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn helper_reads_complete_input_before_acquiring_emission_lock() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let packet = managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        &vec![b'I'; MAX_FRAME_BYTES],
    );
    let owner = acquire(&root, LockKind::PolicyEmission);
    let (mut child, feeder) = start_helper(packet);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !feeder.is_finished() && Instant::now() < deadline {
        thread::yield_now();
    }
    assert!(feeder.is_finished());
    feeder.join().unwrap().unwrap();
    // The entire input was consumed although no emission gate was available.
    child.kill().unwrap();
    child.wait().unwrap();
    drop(owner);
    let output = child.wait_with_output().unwrap();
    assert!(output.stdout.is_empty());
}

#[test]
fn stalled_helper_prevents_revoke_settlement_until_killed_then_no_post_ack_writes() {
    let (_temp, root, store) = setup();
    let source = root.join("synthetic.jsonl");
    std::fs::write(&source, b"synthetic").unwrap();
    let selected = store
        .add_selection(
            ControlSeq::new(0).unwrap(),
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Claude,
                    locator: CanonicalLocator::from_path(&source.canonicalize().unwrap()).unwrap(),
                    kind: RootKind::Exact,
                },
                root_identity: Some(id("root")),
                now_ms: 1,
            },
        )
        .unwrap();
    let policy = store.status().unwrap().policy;
    let frame = vec![b'Q'; MAX_FRAME_BYTES];
    let (mut child, feeder) = start_helper(managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        &frame,
    ));
    let mut status = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let status_task = thread::spawn(move || {
        let mut ready = [0];
        let result = status.read_exact(&mut ready).map(|_| ready);
        let _ = tx.send(result);
    });
    let ready = rx.recv_timeout(Duration::from_secs(5));
    if ready.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("no ready signal");
    }
    assert_eq!(ready.unwrap().unwrap(), [1]);
    feeder.join().unwrap().unwrap();
    status_task.join().unwrap();
    assert!(child.try_wait().unwrap().is_none());
    let owner = acquire(&root, LockKind::PolicyOwner);
    let revoked = store
        .revoke_selection(policy.control_seq, &selected.value.id, None, 2)
        .unwrap();
    assert!(matches!(
        ExclusiveGuard::try_acquire(&root, LockKind::PolicyEmission),
        Err(PortError::WriterBusy(_))
    ));
    // Only this owned helper is killed, never a host. Its actual exit is observed.
    child.kill().unwrap();
    child.wait().unwrap();
    let drain = acquire(&root, LockKind::PolicyEmission);
    store
        .settle_revocation(
            revoked.control_seq,
            &owner,
            &drain,
            &revoked.value.intent.id,
            3,
        )
        .unwrap();
    // Bytes already accepted before kill may remain buffered. Drain them after
    // acknowledgement and require EOF: no live emitter can append more bytes.
    let mut accepted = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut accepted)
        .unwrap();
    assert!(accepted.len() < frame.len());
    assert!(accepted.iter().all(|b| *b == b'Q'));
    drop(drain);
    drop(owner);
    let output = complete_helper(managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        b"old epoch\n",
    ));
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
}

#[test]
fn parent_supervisor_cancels_stalled_output_with_original_deadline() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(3);
    let failure = managed_emit::emit_using(
        binary(),
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        &vec![b'S'; MAX_FRAME_BYTES],
        deadline,
        Stdio::piped(),
    )
    .unwrap_err();
    assert_eq!(failure.kind(), EmissionFailureKind::Deadline);
    assert!(Instant::now() < deadline);
    assert!(failure.into_pending().is_none());
    drop(acquire(&root, LockKind::PolicyEmission));
}

#[test]
fn parent_exact_output_error_mapping_and_rejected_frame_have_no_content() {
    let (temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let output_path = temp.path().join("output");
    let output = std::fs::File::create(&output_path).unwrap();
    let frame = b"exact parent frame\n";
    assert_eq!(
        managed_emit::emit_using(
            binary(),
            &root,
            &policy.installation_id,
            policy.policy_epoch,
            frame,
            Instant::now() + Duration::from_secs(5),
            Stdio::from(output)
        )
        .unwrap(),
        EmissionOutcome::Completed
    );
    assert_eq!(std::fs::read(&output_path).unwrap(), frame);
    let output = std::fs::File::create(&output_path).unwrap();
    let error = managed_emit::emit_using(
        binary(),
        &root,
        &policy.installation_id,
        PolicyEpoch::new(999).unwrap(),
        frame,
        Instant::now() + Duration::from_secs(5),
        Stdio::from(output),
    )
    .unwrap_err();
    assert_eq!(error.kind(), EmissionFailureKind::PolicyChanged);
    assert!(std::fs::read(&output_path).unwrap().is_empty());
    let error = managed_emit::emit_using(
        binary(),
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        &vec![0; MAX_FRAME_BYTES + 1],
        Instant::now() + Duration::from_secs(1),
        Stdio::null(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), EmissionFailureKind::InvalidFrame);
    // Expired calls fail before spawning, so using this test process as the
    // current executable cannot accidentally dispatch an unrecognized helper.
    assert_eq!(
        managed_emit::emit_frame(
            &root,
            agent_session_grep_adapters_sqlite::managed_locks::RootIdentity::read(&root).unwrap(),
            &policy.installation_id,
            policy.policy_epoch,
            b"",
            Instant::now()
        )
        .unwrap_err()
        .kind(),
        EmissionFailureKind::Deadline
    );
    assert!(managed_emit::intercept(&["ordinary".into()]).is_none());
}

#[test]
fn helper_broken_pipe_is_normal_and_releases_lock() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let packet = managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        &vec![b'P'; 128 * 1024],
    );
    let (mut child, feeder) = start_helper(packet);
    drop(child.stdout.take());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("pipe closure failed");
        }
        thread::sleep(Duration::from_millis(1));
    }
    feeder.join().unwrap().unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
    drop(acquire(&root, LockKind::PolicyEmission));
}

#[test]
fn maintenance_fence_and_missing_control_fail_without_output_or_creation() {
    use agent_session_grep_ports::control::{MaintenanceFence, MaintenancePhase, MaintenanceState};
    let (_temp, root, store) = setup();
    let owner = id("maintenance_owner");
    store
        .set_maintenance(
            ControlSeq::new(0).unwrap(),
            &owner,
            MaintenanceFence {
                state: MaintenanceState::Updating,
                owner: Some(owner.clone()),
                phase: Some(MaintenancePhase::Quiescing),
            },
        )
        .unwrap();
    let policy = store.status().unwrap().policy;
    let packet = managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        b"must not appear\n",
    );
    let output = complete_helper(packet.clone());
    assert_eq!(output.status.code(), Some(10));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    drop(store);
    std::fs::remove_file(SqliteControlStore::path(&root)).unwrap();
    let output = complete_helper(packet);
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!SqliteControlStore::path(&root).exists());
    drop(acquire(&root, LockKind::PolicyEmission));
}

#[test]
fn captured_root_mismatch_rejects_parent_before_spawn() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let other = agent_session_grep_testkit::tempdir().unwrap();
    let wrong = agent_session_grep_adapters_sqlite::managed_locks::RootIdentity::read(other.path())
        .unwrap();
    let failure = managed_emit::emit_frame(
        &root,
        wrong,
        &policy.installation_id,
        policy.policy_epoch,
        b"forbidden",
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(failure.kind(), EmissionFailureKind::PolicyChanged);
}

#[test]
fn maximum_frame_survives_input_transfer_and_complete_output() {
    let (temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let path = temp.path().join("maximum-frame");
    let output = std::fs::File::create(&path).unwrap();
    let frame = (0..MAX_FRAME_BYTES)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let result = managed_emit::emit_using(
        binary(),
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        &frame,
        Instant::now() + Duration::from_secs(5),
        Stdio::from(output),
    )
    .unwrap();
    assert_eq!(result, EmissionOutcome::Completed);
    assert_eq!(std::fs::read(path).unwrap(), frame);
    drop(acquire(&root, LockKind::PolicyEmission));
}

#[test]
fn control_frame_has_exact_bytes_and_needs_no_catalog_or_control_root() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let output_path = temp.path().join("control-frame");
    let frame = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
    let result = managed_emit::emit_control_using_for_test(
        binary(),
        frame,
        Instant::now() + Duration::from_secs(3),
        Stdio::from(std::fs::File::create(&output_path).unwrap()),
    )
    .unwrap();
    assert_eq!(result, EmissionOutcome::Completed);
    assert_eq!(std::fs::read(&output_path).unwrap(), frame);
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    let direct = complete_named_helper(
        INTERNAL_CONTROL_COMMAND,
        managed_emit::control_packet_for_test(frame),
    );
    assert_eq!(direct.status.code(), Some(0));
    assert_eq!(direct.stdout, frame);
    assert_eq!(direct.stderr, [1]);
}

#[test]
fn control_frames_survive_maintenance_pending_deny_and_exclusive_evidence_gate() {
    use agent_session_grep_ports::control::{MaintenanceFence, MaintenancePhase, MaintenanceState};
    let (_temp, root, store) = setup();
    let source = root.join("synthetic.jsonl");
    std::fs::write(&source, b"synthetic").unwrap();
    let selected = store
        .add_selection(
            ControlSeq::new(0).unwrap(),
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Claude,
                    locator: CanonicalLocator::from_path(&source.canonicalize().unwrap()).unwrap(),
                    kind: RootKind::Exact,
                },
                root_identity: Some(id("synthetic_root")),
                now_ms: 1,
            },
        )
        .unwrap();
    store
        .revoke_selection(selected.control_seq, &selected.value.id, None, 2)
        .unwrap();
    let owner = id("synthetic_maintenance");
    store
        .set_maintenance(
            store.status().unwrap().policy.control_seq,
            &owner,
            MaintenanceFence {
                state: MaintenanceState::Updating,
                owner: Some(owner.clone()),
                phase: Some(MaintenancePhase::Quiescing),
            },
        )
        .unwrap();
    let before = store.status().unwrap();
    let drain = acquire(&root, LockKind::PolicyEmission);
    let owner_guard = acquire(&root, LockKind::PolicyOwner);
    let catalog_guard = acquire(&root, LockKind::CatalogHandles);
    let frame = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"reason\":\"scope_revoking\"}}\n";
    let output = complete_named_helper(
        INTERNAL_CONTROL_COMMAND,
        managed_emit::control_packet_for_test(frame),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, frame);
    assert_eq!(output.stderr, [1]);
    assert_eq!(store.status().unwrap(), before);
    let evidence = complete_helper(managed_emit::packet_for_test(
        &root,
        &before.policy.installation_id,
        before.policy.policy_epoch,
        b"must remain fenced\n",
    ));
    assert_eq!(evidence.status.code(), Some(10));
    assert!(evidence.stdout.is_empty());
    assert!(evidence.stderr.is_empty());
    drop(catalog_guard);
    drop(owner_guard);
    drop(drain);
    drop(store);
    // Missing control cannot hide a content-free error or cause recreation.
    std::fs::remove_file(SqliteControlStore::path(&root)).unwrap();
    let output = complete_named_helper(
        INTERNAL_CONTROL_COMMAND,
        managed_emit::control_packet_for_test(frame),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, frame);
    assert!(!SqliteControlStore::path(&root).exists());
}

#[test]
fn control_helper_rejects_malformed_cross_protocol_and_incomplete_frames() {
    let (_temp, root, store) = setup();
    let policy = store.status().unwrap().policy;
    let evidence = managed_emit::packet_for_test(
        &root,
        &policy.installation_id,
        policy.policy_epoch,
        b"evidence\n",
    );
    let control = managed_emit::control_packet_for_test(b"control\n");
    let mut oversized = control.clone();
    oversized[8..12].copy_from_slice(&((MAX_FRAME_BYTES + 1) as u32).to_le_bytes());
    let mut trailing = control.clone();
    trailing.push(0);
    let truncated = control[..control.len() - 1].to_vec();
    for packet in [
        b"invalid".to_vec(),
        oversized,
        trailing,
        truncated,
        evidence,
    ] {
        let output = complete_named_helper(INTERNAL_CONTROL_COMMAND, packet);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    // A control header cannot downgrade the existing evidence helper.
    let output = complete_helper(control);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let output = Command::new(binary())
        .args([INTERNAL_CONTROL_COMMAND, "unexpected"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn control_parent_preserves_exact_cap_and_rejects_oversize_or_expired_before_spawn() {
    let frame = (0..MAX_FRAME_BYTES)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let (reader, writer) = std::io::pipe().unwrap();
    let collected = thread::spawn(move || {
        let mut reader = reader;
        let mut output = Vec::with_capacity(MAX_FRAME_BYTES);
        reader.read_to_end(&mut output).unwrap();
        output
    });
    let result = managed_emit::emit_control_using_for_test(
        binary(),
        &frame,
        Instant::now() + Duration::from_secs(5),
        Stdio::from(writer),
    )
    .unwrap();
    assert_eq!(result, EmissionOutcome::Completed);
    assert_eq!(collected.join().unwrap(), frame);
    // Expiry and size failure must not dispatch this test executable as a helper.
    assert_eq!(
        managed_emit::emit_control_frame(b"", Instant::now())
            .unwrap_err()
            .kind(),
        EmissionFailureKind::Deadline
    );
    assert_eq!(
        managed_emit::emit_control_frame(
            &vec![0; MAX_FRAME_BYTES + 1],
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err()
        .kind(),
        EmissionFailureKind::InvalidFrame
    );
}

#[test]
fn control_parent_cancels_blocked_pipe_and_confirms_owned_helper_exit() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(3);
    let error = managed_emit::emit_control_using_for_test(
        binary(),
        &vec![b' '; MAX_FRAME_BYTES],
        deadline,
        Stdio::piped(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), EmissionFailureKind::Deadline);
    assert!(Instant::now() < deadline);
    // supervise/cancel can remove PendingEmission only after try_wait and both
    // input/status tasks complete. A cancellation request alone is insufficient.
    assert!(error.into_pending().is_none());
}

#[test]
fn control_helper_broken_pipe_is_normal_and_exits() {
    let (mut child, feeder) = start_named_helper(
        INTERNAL_CONTROL_COMMAND,
        managed_emit::control_packet_for_test(&vec![b' '; 128 * 1024]),
    );
    drop(child.stdout.take());
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("control helper did not exit after pipe closure");
        }
        thread::sleep(Duration::from_millis(1));
    }
    feeder.join().unwrap().unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
}
