//! Actual CLI control flows over synthetic private profiles. No user settings.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, LockKind},
};
use agent_session_grep_ports::{PortError, SearchProvider, control::*};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");

/// Automatic revoke starts its own cleanup owner even while updates are paused.
/// Retain this fixture until the owner actually exits, then let TempDir remove
/// synthetic state. Stop updates alone cannot stop owned revocation cleanup.
struct PrivateFixture(tempfile::TempDir);
impl PrivateFixture {
    fn new() -> Self {
        Self(agent_session_grep_testkit::tempdir().unwrap())
    }
    fn path(&self) -> &Path {
        self.0.path()
    }
}
impl Drop for PrivateFixture {
    fn drop(&mut self) {
        let Ok(entries) = std::fs::read_dir(self.path()) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("synthetic fixture entry");
            let root = entry.path();
            if !entry.file_type().unwrap().is_dir() || !root.join("control.db").exists() {
                continue;
            }
            assert_eq!(root.parent(), Some(self.path()));
            let end = Instant::now() + Duration::from_secs(2);
            let control = match SqliteControlStore::open_current_writable(&root) {
                Ok(control) => control,
                // Deliberate corrupt-schema fixtures cause the private worker
                // itself to fail closed; they have no valid maintenance API.
                Err(PortError::SchemaIncompatible(_) | PortError::NotFound(_)) => continue,
                Err(error) => panic!("fixture control unavailable during drain: {error:?}"),
            };
            let operation = ControlId::parse("synthetic_fixture_cleanup").unwrap();
            loop {
                let current = control.status().unwrap();
                if current.policy.maintenance.state != MaintenanceState::Idle {
                    break;
                }
                match control.set_maintenance(
                    current.policy.control_seq,
                    &operation,
                    MaintenanceFence {
                        state: MaintenanceState::Uninstalling,
                        owner: Some(operation.clone()),
                        phase: Some(MaintenancePhase::Quiescing),
                    },
                ) {
                    Ok(_) => break,
                    Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                        if Instant::now() < end =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("fixture could not request owned drain: {error:?}"),
                }
            }
            let kind =
                agent_session_grep_adapters_sqlite::managed_purge::purge_lock_kind().unwrap();
            loop {
                match ExclusiveGuard::try_acquire(&root, kind.clone()) {
                    Ok(guard) => {
                        drop(guard);
                        break;
                    }
                    Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("fixture purge owner did not drain: {error:?}"),
                }
            }
        }
    }
}
fn run(db: &Path, args: &[&str]) -> Output {
    let owned_db = db.to_path_buf();
    let owned_args: Vec<_> = args.iter().map(|s| s.to_string()).collect();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let output = Command::new(BIN)
            .args(["--robot", "--db"])
            .arg(owned_db)
            .args(owned_args)
            .output();
        let _sent = sender.send(output);
    });
    match receiver.recv_timeout(Duration::from_secs(8)) {
        Ok(output) => output.unwrap(),
        Err(_) => {
            // Release only this test's worker through durable intent so a
            // leaked inherited pipe cannot hang the entire test executable.
            let _stop = Command::new(BIN)
                .args(["--robot", "--db"])
                .arg(db)
                .args(["background", "stop"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            panic!("CLI process/pipe lifetime exceeded the bounded command budget");
        }
    }
}
fn data(output: &Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
}

fn acquire(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("synthetic lock failed: {error:?}"),
        }
    }
}

fn add(db: &Path, path: &Path) -> Value {
    data(
        &run(
            db,
            &[
                "sources",
                "add",
                "--provider",
                "claude",
                path.to_str().unwrap(),
            ],
        ),
        0,
    )
}

fn setup_paused(db: &Path) {
    data(&run(db, &["setup"]), 10);
    // No worker has run yet, so the pause transition completes immediately.
    data(&run(db, &["background", "pause"]), 0);
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !predicate() {
        assert!(Instant::now() < deadline, "synthetic state timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn setup_selection_pause_revoke_and_reopen_preserve_policy_and_sources() {
    let temp = PrivateFixture::new();
    let db = temp.path().join("private").join("catalog.db");
    let sources = temp.path().join("history");
    std::fs::create_dir(&sources).unwrap();
    let transcript = sources.join("synthetic.jsonl");
    std::fs::write(&transcript, b"synthetic original bytes").unwrap();
    let setup = data(&run(&db, &["setup"]), 10);
    assert_eq!(setup["stages"]["catalog"], "ready");
    assert_eq!(setup["stages"]["host_registration"], "pending");
    let again = data(&run(&db, &["setup"]), 10);
    assert_eq!(again["control_seq"], setup["control_seq"]);
    data(&run(&db, &["background", "pause"]), 0);
    let selected = data(
        &run(
            &db,
            &[
                "sources",
                "add",
                "--provider",
                "claude",
                sources.to_str().unwrap(),
            ],
        ),
        0,
    );
    let id = selected["id"].as_str().unwrap();
    let repeat = data(
        &run(
            &db,
            &[
                "sources",
                "add",
                "--provider",
                "claude",
                sources.to_str().unwrap(),
            ],
        ),
        0,
    );
    assert_eq!(repeat["changed"], false);
    assert_eq!(repeat["id"], id);
    let paused = data(&run(&db, &["background", "pause"]), 0);
    assert_eq!(paused["desired_updates"], "paused");
    let revoked = data(&run(&db, &["sources", "revoke", id]), 0);
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(revoked["cleanup_pending"], true);
    let status = data(&run(&db, &["background", "status"]), 0);
    assert_eq!(status["desired_updates"], "paused");
    assert_eq!(status["selected_count"], 0);
    let control = SqliteControlStore::open_current_read_only(db.parent().unwrap()).unwrap();
    let policy = control.read_policy(RequestIntersection::Selected).unwrap();
    assert!(!policy.allows_source(
        SearchProvider::Claude,
        &CanonicalLocator::from_path(&transcript.canonicalize().unwrap()).unwrap(),
        &ControlId::parse("source").unwrap()
    ));
    assert_eq!(
        std::fs::read(&transcript).unwrap(),
        b"synthetic original bytes"
    );
    let listing = run(&db, &["sources", "list"]);
    assert!(!String::from_utf8_lossy(&listing.stdout).contains(sources.to_str().unwrap()));
}

#[test]
fn invalid_help_and_missing_control_do_not_create_a_catalog() {
    let temp = PrivateFixture::new();
    let db = temp.path().join("absent").join("catalog.db");
    assert!(run(&db, &["setup", "--help"]).status.success());
    assert_eq!(run(&db, &["setup", "--unknown"]).status.code(), Some(2));
    let background = run(&db, &["background", "status"]);
    assert!(
        matches!(background.status.code(), Some(4) | Some(5)),
        "missing control must fail without creating state: {}",
        String::from_utf8_lossy(&background.stdout)
    );
    assert!(!db.parent().unwrap().exists());
}

#[test]
fn setup_rejects_legacy_and_revoke_waits_for_real_emission_owner() {
    let temp = PrivateFixture::new();
    let legacy = temp.path().join("legacy.db");
    std::fs::write(&legacy, b"legacy marker").unwrap();
    assert_eq!(run(&legacy, &["setup"]).status.code(), Some(9));
    assert_eq!(std::fs::read(&legacy).unwrap(), b"legacy marker");
    assert!(!temp.path().join("control.db").exists());
    let db = temp.path().join("private").join("catalog.db");
    setup_paused(&db);
    let selected = data(
        &run(
            &db,
            &[
                "sources",
                "add",
                "--provider",
                "codex",
                temp.path().to_str().unwrap(),
            ],
        ),
        0,
    );
    let guard = acquire(db.parent().unwrap(), LockKind::PolicyEmission);
    let blocked = data(
        &run(
            &db,
            &["sources", "revoke", selected["id"].as_str().unwrap()],
        ),
        10,
    );
    assert_eq!(blocked["status"], "scope_revoking");
    assert_eq!(blocked["denial_active"], true);
    drop(guard);
    let done = data(
        &run(
            &db,
            &["sources", "revoke", selected["id"].as_str().unwrap()],
        ),
        0,
    );
    assert_eq!(done["status"], "revoked");
}

#[cfg(windows)]
#[test]
fn invalid_catalog_aliases_fail_before_setup_creates_any_state() {
    let temp = PrivateFixture::new();
    for (index, name) in [
        "catalog.db.",
        "catalog.db ",
        "catalog.db:history",
        "CON.db",
        " catalog.db",
    ]
    .iter()
    .enumerate()
    {
        let parent = temp.path().join(format!("absent-{index}"));
        assert_eq!(run(&parent.join(name), &["setup"]).status.code(), Some(2));
        assert!(!parent.exists(), "invalid path created setup state");
    }
    let existing = temp.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    std::fs::write(existing.join("catalog.db"), b"synthetic existing catalog").unwrap();
    assert_eq!(
        run(&existing.join("catalog.db."), &["setup"]).status.code(),
        Some(2)
    );
    assert_eq!(
        std::fs::read(existing.join("catalog.db")).unwrap(),
        b"synthetic existing catalog"
    );
    assert_eq!(std::fs::read_dir(existing).unwrap().count(), 1);
}

#[test]
fn add_reports_policy_delta_overlap_and_preserved_exclusions() {
    let temp = PrivateFixture::new();
    let db = temp.path().join("private/catalog.db");
    let history = temp.path().join("history");
    let child = history.join("child");
    std::fs::create_dir_all(&child).unwrap();
    setup_paused(&db);
    let parent = add(&db, &history);
    assert_eq!(parent["policy_effect"]["effective_permission"], "eligible");
    assert_eq!(parent["policy_effect"]["scope_delta"], "expanded");
    assert_eq!(parent["background_start"]["reason"], "paused");
    let repeat = add(&db, &history);
    assert_eq!(repeat["changed"], false);
    assert_eq!(repeat["policy_effect"]["scope_delta"], "unchanged");
    let selected_child = add(&db, &child);
    assert_eq!(selected_child["policy_effect"]["scope_delta"], "unchanged");
    data(
        &run(
            &db,
            &["sources", "revoke", selected_child["id"].as_str().unwrap()],
        ),
        0,
    );
    let restricted = add(&db, &history);
    assert_eq!(
        restricted["policy_effect"]["effective_permission"],
        "restricted"
    );
    assert_eq!(restricted["policy_effect"]["locator_exclusion_count"], 1);
    data(
        &run(&db, &["sources", "revoke", parent["id"].as_str().unwrap()]),
        0,
    );
    let blocked = add(&db, &history);
    assert_eq!(blocked["enabled"], true);
    assert_eq!(blocked["changed"], true);
    assert_eq!(blocked["policy_effect"]["effective_permission"], "blocked");
    assert_eq!(blocked["policy_effect"]["scope_delta"], "unchanged");
    assert!(!blocked.to_string().contains(history.to_str().unwrap()));
    let status = data(&run(&db, &["background", "status"]), 0);
    assert_eq!(
        status["selected_count_basis"],
        "enabled_selections_before_exclusions"
    );
    assert_eq!(status["desired_updates"], "paused");
    assert_eq!(status["running"], false);
}

#[test]
fn exact_revoke_preserves_physical_source_deny_across_hardlink_and_repeat() {
    let temp = PrivateFixture::new();
    let db = temp.path().join("private/catalog.db");
    let original = temp.path().join("original.jsonl");
    let alias = temp.path().join("alias.jsonl");
    std::fs::write(&original, b"synthetic source").unwrap();
    std::fs::hard_link(&original, &alias).unwrap();
    setup_paused(&db);
    let selected = add(&db, &original);
    add(&db, &alias);
    let locator = CanonicalLocator::from_path(&original.canonicalize().unwrap()).unwrap();
    let alias_locator = CanonicalLocator::from_path(&alias.canonicalize().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("INSERT INTO source_bindings(source_id,source_path,provider_id,namespace_id,root_identity,bound_at_ms) VALUES('physical_source',?1,?2,NULL,'synthetic_root',1)", [locator.as_str(), SearchProvider::Claude.as_str()]).unwrap();
    conn.execute(
        "INSERT INTO source_heads(source_id,update_state) VALUES('physical_source','unknown')",
        [],
    )
    .unwrap();
    drop(conn);
    for _ in 0..2 {
        let result = data(
            &run(
                &db,
                &["sources", "revoke", selected["id"].as_str().unwrap()],
            ),
            0,
        );
        assert_eq!(result["denial_active"], true);
        let control = SqliteControlStore::open_current_read_only(db.parent().unwrap()).unwrap();
        let policy = control.read_policy(RequestIntersection::Selected).unwrap();
        let source = ControlId::parse("physical_source").unwrap();
        assert!(!policy.allows_source(SearchProvider::Claude, &locator, &source));
        assert!(!policy.allows_source(SearchProvider::Claude, &alias_locator, &source));
        assert!(policy.allows_source(
            SearchProvider::Claude,
            &alias_locator,
            &ControlId::parse("different_source").unwrap()
        ));
        assert_eq!(
            policy
                .exclusions
                .iter()
                .filter(|e| matches!(e.region, ExcludedRegion::SourceIdentity { .. }))
                .count(),
            1
        );
    }
    assert_eq!(std::fs::read(original).unwrap(), b"synthetic source");
    assert_eq!(std::fs::read(alias).unwrap(), b"synthetic source");
}

#[test]
fn exact_revoke_absent_binding_is_allowed_but_catalog_errors_are_not_absence() {
    let temp = PrivateFixture::new();
    let source = temp.path().join("synthetic.jsonl");
    std::fs::write(&source, b"synthetic bytes").unwrap();
    // Interrupted setup: control exists but has never bound a catalog.
    let db = temp.path().join("before-catalog/catalog.db");
    SqliteControlStore::create(
        db.parent().unwrap(),
        &ControlId::parse("synthetic_installation").unwrap(),
        DesiredUpdates::Paused,
    )
    .unwrap();
    let selected = add(&db, &source);
    data(
        &run(
            &db,
            &["sources", "revoke", selected["id"].as_str().unwrap()],
        ),
        0,
    );
    assert!(!db.exists());

    let db = temp.path().join("corrupt-catalog/catalog.db");
    setup_paused(&db);
    let selected = add(&db, &source);
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch("DROP TABLE source_heads").unwrap();
    drop(conn);
    let failed = run(
        &db,
        &["sources", "revoke", selected["id"].as_str().unwrap()],
    );
    assert!(!failed.status.success());
    assert_ne!(failed.status.code(), Some(10));
    let control = SqliteControlStore::open_current_read_only(db.parent().unwrap()).unwrap();
    let policy = control.read_policy(RequestIntersection::Selected).unwrap();
    assert!(policy.selections[0].enabled);
    assert!(policy.exclusions.is_empty());
    assert!(!String::from_utf8_lossy(&failed.stdout).contains("source_heads"));
}

fn settlement_contention(release_early: bool) {
    let temp = PrivateFixture::new();
    let db = temp.path().join("private/catalog.db");
    let history = temp.path().join("history");
    std::fs::create_dir(&history).unwrap();
    setup_paused(&db);
    let selected = add(&db, &history);
    let root = db.parent().unwrap();
    let emission = acquire(root, LockKind::PolicyEmission);
    let started = Instant::now();
    let child = Command::new(BIN)
        .args(["--robot", "--db"])
        .arg(&db)
        .args(["sources", "revoke", selected["id"].as_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let control = SqliteControlStore::open_current_read_only(root).unwrap();
    wait_until(|| {
        control
            .status()
            .unwrap()
            .policy
            .revocations
            .iter()
            .any(|r| r.state == RevocationState::AwaitingDrain)
    });
    let writer = rusqlite::Connection::open(SqliteControlStore::path(root)).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    drop(emission);
    if release_early {
        // Deliberately exceed the adapter's single 250ms busy timeout.
        std::thread::sleep(Duration::from_millis(450));
        writer.execute_batch("ROLLBACK").unwrap();
    }
    let result = data(
        &child.wait_with_output().unwrap(),
        if release_early { 0 } else { 10 },
    );
    assert!(started.elapsed() < Duration::from_millis(5500));
    assert_eq!(result["denial_active"], true);
    if release_early {
        assert_eq!(result["status"], "revoked");
    } else {
        assert_eq!(result["status"], "scope_revoking");
        assert_eq!(result["reason"], "settlement_busy");
        assert_eq!(result["cleanup_pending"], true);
        assert!(
            control
                .status()
                .unwrap()
                .policy
                .revocations
                .iter()
                .any(|r| r.state == RevocationState::AwaitingDrain)
        );
        writer.execute_batch("ROLLBACK").unwrap();
        data(
            &run(
                &db,
                &["sources", "revoke", selected["id"].as_str().unwrap()],
            ),
            0,
        );
    }
}

#[test]
fn durable_deny_retries_settlement_after_writer_is_released() {
    settlement_contention(true);
}

#[test]
fn durable_deny_reports_partial_at_original_deadline_under_writer_lock() {
    settlement_contention(false);
}

// Own only the worker launched into this synthetic profile. Stop through its
// durable control API even if an assertion fails; never kill an unrelated PID.
struct StopWorker(PathBuf);
impl Drop for StopWorker {
    fn drop(&mut self) {
        let _output = run(&self.0, &["background", "stop"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let output = run(&self.0, &["background", "status"]);
            if serde_json::from_slice::<Value>(&output.stdout)
                .is_ok_and(|v| v["data"]["running"] == false)
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[test]
fn selected_history_start_pause_resume_stop_uses_actual_worker_liveness() {
    let temp = PrivateFixture::new();
    let db = temp.path().join("private/catalog.db");
    let history = temp.path().join("history");
    std::fs::create_dir(&history).unwrap();
    let source = history.join("synthetic.jsonl");
    let mut bytes = serde_json::to_vec(&json!({"type":"user","uuid":"synthetic-message","sessionId":"synthetic-session","timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":"synthetic lifecycle evidence"}})).unwrap();
    bytes.push(b'\n');
    std::fs::write(&source, &bytes).unwrap();
    let _stop = StopWorker(db.clone());
    let setup = data(&run(&db, &["setup"]), 10);
    assert_eq!(setup["background_start"]["reason"], "no_enabled_selections");
    let selected = add(&db, &history);
    assert_eq!(selected["background_start"]["verified_running"], true);
    wait_until(|| {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.query_row(
            "SELECT count(*) FROM source_revision_receipts WHERE published=1",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    });
    let running = data(&run(&db, &["background", "status"]), 0);
    assert_eq!(running["running"], true);
    assert_eq!(running["latest_satisfied"], false);
    let again = data(&run(&db, &["background", "start"]), 0);
    assert_eq!(again["already_running"], true);
    assert_eq!(again["verified_running"], true);
    let paused = data(&run(&db, &["background", "pause"]), 10);
    assert_eq!(paused["requested_updates"], "paused");
    let declined = data(&run(&db, &["background", "start"]), 10);
    assert_eq!(declined["reason"], "paused");
    assert_eq!(add(&db, &history)["background_start"]["reason"], "paused");
    let setup_again = data(&run(&db, &["setup"]), 10);
    assert_eq!(setup_again["desired_updates"], "paused");
    assert_eq!(setup_again["stages"]["host_registration"], "pending");
    // Paused worker can still hold its OS lock. Resume must not claim confirmed
    // activity from a stale paused heartbeat; either ready or explicit partial.
    let resumed_output = run(&db, &["background", "resume"]);
    assert!(matches!(resumed_output.status.code(), Some(0 | 10)));
    let resumed: Value = serde_json::from_slice(&resumed_output.stdout).unwrap();
    assert_eq!(resumed["data"]["requested_updates"], "running");
    let stopped = data(&run(&db, &["background", "stop"]), 10);
    assert_eq!(stopped["requested_updates"], "stopped");
    wait_until(|| data(&run(&db, &["background", "status"]), 0)["running"] == false);
    let offline = data(&run(&db, &["background", "status"]), 0);
    assert_eq!(offline["effective_state"], "offline");
    assert_eq!(offline["desired_updates"], "stopped");
    assert_eq!(
        data(&run(&db, &["background", "start"]), 10)["reason"],
        "stopped"
    );
    assert_eq!(std::fs::read(source).unwrap(), bytes);
    assert!(!String::from_utf8_lossy(&resumed_output.stdout).contains(history.to_str().unwrap()));
}
