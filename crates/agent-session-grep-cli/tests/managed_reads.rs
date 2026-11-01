//! Actual CLI reads over synthetic managed catalogs; no real assistant history.
use agent_session_grep_adapters_sqlite::{
    PARSER_SEMANTIC_VERSION, SourceActivity, SourceBatch, SqliteControlStore,
    control::BackupPurpose,
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind},
    managed_maintenance::{
        BackupOutcome, MaintenanceCatalog, RestoreOutcome, apply_restore, prepare_restore,
        verify_backup_until,
    },
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{
    EvidenceSpan, IdKind, MessageEdge, MessagePlacement, MessageRelation, StableId, ToolActivity,
    ToolActivityActor, ToolActivityKind, ToolActivityStatus,
};
use agent_session_grep_ports::{
    PortError, SearchProvider, SourceResumeClaim,
    control::*,
    managed::{
        ObservationState, RepositoryClaim, RevisionId, SelectionProof, SourceBinding, SourceId,
        SourceObservation,
    },
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::mpsc::{Receiver, channel},
    thread::JoinHandle,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn entity(kind: IdKind, name: &str) -> StableId {
    StableId::native_checked(kind, name).unwrap()
}
fn lock(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(g) => return g,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => std::thread::yield_now(),
            Err(e) => panic!("fixture lock: {e:?}"),
        }
    }
}
fn current(control: &SqliteControlStore) -> ControlSeq {
    control.status().unwrap().policy.control_seq
}
struct Fixture {
    root: PathBuf,
    db: PathBuf,
    control: SqliteControlStore,
    selection: ControlId,
    message: StableId,
    system: StableId,
    session: StableId,
    batch: SourceBatch,
    observation: SourceObservation,
    // Connections and OS guards must close before Windows temp cleanup.
    _temp: tempfile::TempDir,
}
impl Fixture {
    fn new(count: usize, text: &str) -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let db = root.join("catalog.db");
        let control =
            SqliteControlStore::create(&root, &id("private-installation"), DesiredUpdates::Running)
                .unwrap();
        let selection = control
            .add_selection(
                current(&control),
                SelectionRequest {
                    region: ScopeRegion {
                        provider: SearchProvider::Claude,
                        locator: CanonicalLocator::from_path(&temp.path().canonicalize().unwrap())
                            .unwrap(),
                        kind: RootKind::Root,
                    },
                    root_identity: Some(id("source-root")),
                    now_ms: 1,
                },
            )
            .unwrap()
            .value;
        let guard = lock(&root, LockKind::Background);
        let worker = control.bind_worker(&guard, id("private-boot")).unwrap();
        control
            .register_worker(current(&control), &worker, 1, 1)
            .unwrap();
        let cycle = match control
            .queue_cycle(
                current(&control),
                vec![SelectionRevision {
                    selection_id: selection.id.clone(),
                    revision: selection.revision,
                    root_identity: id("source-root"),
                }],
            )
            .unwrap()
            .value
        {
            CycleAdmission::Queued(c) => c,
            _ => panic!("cycle"),
        };
        let cycle = control
            .start_cycle(current(&control), &worker, cycle.token.cycle_seq, 2)
            .unwrap()
            .value;
        let message = entity(IdKind::Message, "message-0");
        let system = entity(IdKind::Message, "system");
        let session = entity(IdKind::Session, "session");
        let document = entity(IdKind::Document, "document");
        let observation = SourceObservation {
            binding: SourceBinding {
                source_id: SourceId::parse("PRIVATE_SOURCE_SENTINEL").unwrap(),
                source_path: CanonicalLocator::from_path(&temp.path().join("synthetic.jsonl"))
                    .unwrap()
                    .as_str()
                    .into(),
                provider: SearchProvider::Claude,
                namespace_id: None,
                root_identity: "source-root".into(),
            },
            revision_id: RevisionId::parse("PRIVATE_REVISION_ID").unwrap(),
            revision_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .into(),
            parser_version: PARSER_SEMANTIC_VERSION,
            state: ObservationState::Complete,
            cycle_seq: cycle.token.cycle_seq.get(),
            worker_boot_id: "private-boot".into(),
            catalog_incarnation: "private-incarnation".into(),
            policy_epoch: cycle.policy_epoch.get(),
            started_control_seq: cycle.started_control_seq.unwrap().get(),
            observed_at_ms: 3,
            committed_at_ms: 4,
            selections: vec![SelectionProof {
                selection_id: selection.id.as_str().into(),
                selection_revision: selection.revision.get(),
                root_identity: "source-root".into(),
            }],
            repositories: vec![RepositoryClaim {
                session_id: session.clone(),
                slug: "example.test/team/project".into(),
            }],
        };
        let timestamp = "2026-10-17T12:00:00Z";
        let mut entries=vec![(session.clone(),serde_json::to_vec(&json!({"documents":[document.as_str()],"title":"Synthetic session"})).unwrap(),String::new()),(document.clone(),serde_json::to_vec(&json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":observation.revision_digest,"len":1000000})).unwrap(),String::new())];
        let mut placements = Vec::new();
        let mut edges = Vec::new();
        let mut previous = None;
        for n in 0..count {
            let message = entity(IdKind::Message, &format!("message-{n}"));
            entries.push((
                message.clone(),
                serde_json::to_vec(
                    &json!({"role":"user","text":format!("{text} item {n}"),"timestamp":timestamp}),
                )
                .unwrap(),
                text.into(),
            ));
            let placement = MessagePlacement::new(
                session.clone(),
                document.clone(),
                message.clone(),
                n as u32,
                false,
                Some(EvidenceSpan {
                    start: n as u64 * 100,
                    end: n as u64 * 100 + 90,
                }),
            );
            if let Some(parent) = previous {
                edges.push(MessageEdge {
                    child_placement_id: placement.id.clone(),
                    parent_message_id: parent,
                    parent_native_id: None,
                    relation: MessageRelation::Reply,
                });
            }
            previous = Some(message);
            placements.push(placement);
        }
        let system_placement = MessagePlacement::new(
            session.clone(),
            document.clone(),
            system.clone(),
            count as u32,
            false,
            None,
        );
        if let Some(parent) = previous {
            edges.push(MessageEdge {
                child_placement_id: system_placement.id.clone(),
                parent_message_id: parent,
                parent_native_id: None,
                relation: MessageRelation::Reply,
            });
        }
        placements.push(system_placement);
        entries.push((
            system.clone(),
            serde_json::to_vec(
                &json!({"role":"system","text":"system-secret-content","timestamp":timestamp}),
            )
            .unwrap(),
            "system-secret-content".into(),
        ));
        let batch = SourceBatch {
            source_path: observation.binding.source_path.clone(),
            entries,
            placements,
            edges,
            activities: vec![],
            usage_events: vec![],
            relation_complete: true,
            len_bytes: Some(1000000),
            fingerprint: Some(observation.revision_digest.clone()),
            provider_id: Some("claude-code".into()),
            resume_claims: vec![SourceResumeClaim {
                session_id: session.as_str().into(),
                provider_id: "claude-code".into(),
                provider_session_id: Some("NATIVE_RESUME_SENTINEL".into()),
                provider_session_id_state: "resolved".into(),
                original_working_directory: Some("PRIVATE_CWD_SENTINEL".into()),
                original_working_directory_state: "resolved".into(),
                pair_observed: true,
            }],
        };
        let store = ManagedStore::create(&db, &control, id("private-incarnation"), 1).unwrap();
        store
            .commit_source(&control, &worker, &batch, &observation)
            .unwrap();
        drop(store);
        drop(worker);
        drop(guard);
        Self {
            _temp: temp,
            root,
            db,
            control,
            selection: selection.id,
            message,
            system,
            session,
            batch,
            observation,
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(["--robot", "--db"])
            .arg(&self.db)
            .args(args)
            .output()
            .unwrap()
    }
    fn extra_source_batch(&self) -> (SourceBatch, SourceObservation) {
        let mut observation = self.observation.clone();
        observation.binding.source_id = SourceId::parse("extra-source").unwrap();
        observation.binding.source_path =
            CanonicalLocator::from_path(&self._temp.path().join("extra.jsonl"))
                .unwrap()
                .as_str()
                .into();
        observation.revision_id = RevisionId::parse("extra-receipt").unwrap();
        observation.repositories.clear();
        let mut batch = self.batch.clone();
        batch.source_path = observation.binding.source_path.clone();
        batch.resume_claims.clear();
        batch.edges.clear();
        let session = entity(IdKind::Session, "extra-session");
        let document = entity(IdKind::Document, "extra-document");
        let message = entity(IdKind::Message, "extra-message");
        batch.entries=vec![(session.clone(),serde_json::to_vec(&json!({"documents":[document.as_str()],"title":"extra session"})).unwrap(),String::new()),(document.clone(),serde_json::to_vec(&json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":observation.revision_digest,"len":1000000})).unwrap(),String::new()),(message.clone(),serde_json::to_vec(&json!({"role":"user","text":"needle added after first page","timestamp":"2026-10-17T13:00:00Z"})).unwrap(),"needle".into())];
        batch.placements = vec![MessagePlacement::new(
            session,
            document,
            message,
            0,
            false,
            Some(EvidenceSpan { start: 0, end: 90 }),
        )];
        (batch, observation)
    }
    fn commit_extra_source(&self) {
        let guard = lock(&self.root, LockKind::Background);
        let worker = self
            .control
            .bind_worker(&guard, id("private-boot"))
            .unwrap();
        let store = ManagedStore::open_for_write(&self.db, &self.control).unwrap();
        let (batch, observation) = self.extra_source_batch();
        assert!(
            !store
                .commit_source(&self.control, &worker, &batch, &observation)
                .unwrap()
                .destructive
        );
    }
    fn rewrite_source(&self) {
        let guard = lock(&self.root, LockKind::Background);
        let worker = self
            .control
            .bind_worker(&guard, id("private-boot"))
            .unwrap();
        let store = ManagedStore::open_for_write(&self.db, &self.control).unwrap();
        let mut batch = self.batch.clone();
        let mut observation = self.observation.clone();
        observation.revision_id = RevisionId::parse("rewritten-receipt").unwrap();
        let entry = batch
            .entries
            .iter_mut()
            .find(|(id, _, _)| id == &self.message)
            .unwrap();
        let mut value: Value = serde_json::from_slice(&entry.1).unwrap();
        value["text"] = json!("rewritten needle");
        entry.1 = serde_json::to_vec(&value).unwrap();
        entry.2 = "rewritten needle".into();
        assert!(
            store
                .commit_source(&self.control, &worker, &batch, &observation)
                .unwrap()
                .destructive
        );
    }
    fn spawn(&self, args: &[&str]) -> Child {
        Command::new(BIN)
            .args(["--robot", "--db"])
            .arg(&self.db)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
    fn await_queued_cycle(&self, child: &mut Child, seq: CycleSeq) -> ObservationCycle {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Ok(cycle) = self.control.cycle(seq) {
                assert_eq!(cycle.state, CycleState::Queued);
                return cycle;
            }
            if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("latest child did not admit a queued cycle");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn revoke(&self) {
        let owner = lock(&self.root, LockKind::PolicyOwner);
        let revoked = self
            .control
            .revoke_selection(current(&self.control), &self.selection, None, 10)
            .unwrap();
        let drained = lock(&self.root, LockKind::PolicyEmission);
        self.control
            .settle_revocation(
                revoked.control_seq,
                &owner,
                &drained,
                &revoked.value.intent.id,
                11,
            )
            .unwrap();
    }
}
fn response(output: Output) -> Value {
    assert!(
        matches!(output.status.code(), Some(0 | 10)),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 8192);
    let wire = String::from_utf8(output.stdout).unwrap();
    for private in [
        "PRIVATE_SOURCE_SENTINEL",
        "PRIVATE_REVISION_ID",
        "private-incarnation",
        "private-installation",
        "private-boot",
        "source_path",
        "projection_id",
    ] {
        assert!(!wire.contains(private), "private field escaped: {private}");
    }
    let value: Value = serde_json::from_str(&wire).unwrap();
    assert!(value["data"]["provenance"].is_array());
    assert!(value["data"]["freshness"]["latest_satisfied"].is_boolean());
    assert_eq!(
        value["page"]["has_more"].as_bool().unwrap(),
        value["page"]["next_cursor"].is_string()
    );
    if let Some(cursor) = value["page"]["next_cursor"].as_str() {
        assert!(cursor.starts_with("asgmc1."));
    }
    value
}
fn not_found(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "not_found");
}

#[test]
fn doctor_uses_the_managed_control_path_for_a_real_managed_catalog() {
    let f = Fixture::new(1, "needle");
    let output = f.run(&["doctor"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["data"]["managed"], true);
    assert_eq!(value["data"]["checks"][0]["name"], "catalog");
    assert_eq!(value["data"]["checks"][0]["status"], "ok");
    assert_eq!(value["data"]["diagnostics_complete"], false);
}

#[test]
fn search_show_and_context_share_safe_original_proof() {
    let f = Fixture::new(2, "original evidence");
    let search = response(f.run(&["search", "original"]));
    assert!(!search["data"]["hits"].as_array().unwrap().is_empty());
    assert_eq!(search["outcome"], "partial"); // managed partial must override legacy ADT success
    let proof = search["data"]["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .find(|proof| proof["message_id"] == f.message.as_str())
        .expect("retained Message has its own proof");
    assert_eq!(proof["provider_id"], "claude-code");
    assert_eq!(proof["precision"], "byte");
    assert!(
        proof["document_id"]
            .as_str()
            .unwrap()
            .starts_with("doc_v1_")
    );
    let show = response(f.run(&["show", f.message.as_str()]));
    assert!(
        show["data"]["entity"]["text"]
            .as_str()
            .unwrap()
            .contains("original evidence")
    );
    let context = response(f.run(&["context", f.session.as_str(), "--max-bytes", "8192"]));
    assert!(!context["data"]["messages"].as_array().unwrap().is_empty());
    assert!(!context.to_string().contains("system-secret-content"));
    assert!(!context.to_string().contains("NATIVE_RESUME_SENTINEL"));
    assert!(
        context["data"]["provenance"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["message_id"] == f.message.as_str())
    );
    let message = response(f.run(&[
        "get-message",
        f.message.as_str(),
        "--session",
        f.session.as_str(),
    ]));
    assert_eq!(message["data"]["message_id"], f.message.as_str());
}

#[test]
fn provider_repo_time_and_system_restrictions_apply_to_direct_and_context() {
    let f = Fixture::new(1, "restriction needle");
    for flags in [
        ["--provider", "codex"],
        ["--repo", "example.test/other/project"],
        ["--since", "2026-10-18T00:00:00Z"],
    ] {
        assert!(
            response(f.run(&["search", "needle", flags[0], flags[1]]))["data"]["hits"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        not_found(f.run(&["show", f.message.as_str(), flags[0], flags[1]]));
        not_found(f.run(&["context", f.session.as_str(), flags[0], flags[1]]));
        not_found(f.run(&["get-session-resume", f.session.as_str(), flags[0], flags[1]]));
    }
    assert!(!response(f.run(&["search","needle","--repo","example.test/team/project"]))["data"]["hits"].as_array().unwrap().is_empty());
    not_found(f.run(&["show", f.system.as_str()]));
    let system = response(f.run(&["show", f.system.as_str(), "--include-system"]));
    assert_eq!(system["data"]["entity"]["text"], "system-secret-content");
    // This assertion tests inclusion, with enough Application proof budget for
    // both occurrences. The default 8 KiB case may honestly retain one message.
    let context = response(f.run(&[
        "context",
        f.session.as_str(),
        "--include-system",
        "--max-bytes",
        "32768",
    ]));
    assert!(
        context.to_string().contains("system-secret-content"),
        "{context}"
    );
}

#[test]
fn pause_keeps_evidence_and_latest_is_explicitly_unsatisfied() {
    let f = Fixture::new(1, "paused evidence");
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let show = response(f.run(&["show", f.message.as_str()]));
    assert_eq!(show["data"]["freshness"]["update_state"], "paused");
    let latest = response(f.run(&["search", "paused", "--latest", "--max-wait-ms", "0"]));
    assert_eq!(latest["outcome"], "partial");
    assert_eq!(latest["data"]["freshness"]["latest_requested"], true);
}

#[test]
fn revoked_scope_is_absent_from_search_direct_context_list_and_counts() {
    let f = Fixture::new(2, "revoked evidence");
    let before = response(f.run(&["status"]));
    assert!(before["data"]["catalog_count"].as_u64().unwrap() > 0);
    f.revoke();
    assert!(
        response(f.run(&["search", "revoked"]))["data"]["hits"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    not_found(f.run(&["get", f.message.as_str()]));
    not_found(f.run(&["show", f.message.as_str()]));
    not_found(f.run(&["get-message", f.message.as_str()]));
    not_found(f.run(&["context", f.session.as_str()]));
    not_found(f.run(&["get-session-resume", f.session.as_str()]));
    assert!(
        response(f.run(&["list"]))["data"]["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let status = response(f.run(&["status"]));
    assert_eq!(status["data"]["catalog_count"], 0);
    assert_eq!(status["data"]["placements"], 0);
}

#[test]
fn final_frame_budget_redaction_and_unsupported_commands_are_honest() {
    let f = Fixture::new(
        12,
        &format!(
            "needle {} sk-ant-api03-1234567890abcdef",
            "synthetic ".repeat(80)
        ),
    );
    let raw = f.run(&["search", "needle"]);
    assert!(raw.stdout.len() <= 8192);
    assert!(!String::from_utf8_lossy(&raw.stdout).contains("sk-ant-api03-1234567890abcdef"));
    let value = response(raw);
    assert!(value["data"]["hits"].as_array().unwrap().len() <= 5);
    assert_eq!(value["outcome"], "partial");
    let get = f.run(&["get", f.message.as_str(), "--max-bytes", "4096"]);
    assert!(get.stdout.len() <= 4096);
    assert!(!String::from_utf8_lossy(&get.stdout).contains("sk-ant-api03-1234567890abcdef"));
    let value = response(get);
    assert_eq!(value["redaction"]["status"], "applied");
    let out = f.run(&["resume", f.session.as_str(), "--yes"]);
    assert_eq!(out.status.code(), Some(7));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("NATIVE_RESUME_SENTINEL"));
    assert_eq!(
        f.run(&["search", "needle", "--cursor", "old"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        f.run(&[
            "show",
            f.message.as_str(),
            "--provider",
            "bad-private-value"
        ])
        .status
        .code(),
        Some(2)
    );
}

#[test]
fn managed_handoff_has_original_proof_bounded_redaction_and_scope() {
    let f = Fixture::new(
        3,
        "handoffneedle original text sk-ant-api03-1234567890abcdef",
    );
    let output = f.run(&["handoff", "handoffneedle"]);
    assert!(output.stdout.len() <= 8192);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sk-ant-api03-1234567890abcdef"));
    let frame = response(output);
    assert!(
        !frame["data"]["evidence"].as_array().unwrap().is_empty(),
        "{frame}"
    );
    assert!(!frame["data"]["provenance"].as_array().unwrap().is_empty());
    assert!(
        frame["data"]["source_locators"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["cursor"].is_null())
    );
    let restricted = response(f.run(&["handoff", "handoffneedle", "--provider", "codex"]));
    assert!(
        restricted["data"]["evidence"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.revoke();
    let revoked = response(f.run(&["handoff", "handoffneedle"]));
    assert!(revoked["data"]["evidence"].as_array().unwrap().is_empty());
    assert!(!revoked.to_string().contains("original text"));
}

#[test]
fn missing_control_never_reopens_managed_catalog_as_legacy() {
    let f = Fixture::new(1, "private retained evidence");
    let db = f.db.clone();
    let root = f.root.clone();
    drop(f.control);
    std::fs::remove_file(SqliteControlStore::path(&root)).unwrap();
    let output = Command::new(BIN)
        .args(["--robot", "--db"])
        .arg(db)
        .args(["search", "private"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private retained evidence"));
    assert!(!SqliteControlStore::path(&root).exists());
}

#[test]
fn latest_uses_post_admission_source_and_discovery_receipts_in_output_snapshot() {
    let f = Fixture::new(1, "post admission needle");
    let guard = lock(&f.root, LockKind::Background);
    let worker = f.control.bind_worker(&guard, id("private-boot")).unwrap();
    let store = ManagedStore::open_for_write(&f.db, &f.control).unwrap();
    store.reconcile_progress(&f.control, &worker).unwrap();
    // The fixture's old cycle already observes. A latest request must allocate
    // a distinct queued cycle; holding the writer lease does not block admission.
    let next = f.control.background_status().unwrap().next_cycle_seq;
    let mut child = f.spawn(&["search", "needle", "--latest", "--max-wait-ms", "4000"]);
    let queued = f.await_queued_cycle(&mut child, next);
    assert!(queued.token.cycle_seq.get() > f.observation.cycle_seq);
    let cycle = f
        .control
        .start_cycle(current(&f.control), &worker, next, 10)
        .unwrap()
        .value;
    assert!(cycle.started_control_seq.unwrap() > queued.admitted_control_seq);
    let mut observation = f.observation.clone();
    observation.cycle_seq = cycle.token.cycle_seq.get();
    observation.started_control_seq = cycle.started_control_seq.unwrap().get();
    observation.revision_id = RevisionId::parse("POST_ADMISSION_RECEIPT").unwrap();
    let committed = store
        .commit_source(&f.control, &worker, &f.batch, &observation)
        .unwrap();
    assert!(
        child.try_wait().unwrap().is_none(),
        "source alone cannot satisfy discovery"
    );
    store
        .commit_discovery(
            &f.control,
            &worker,
            &cycle,
            &cycle.selections[0].selection,
            std::slice::from_ref(&observation.binding.source_id),
            11,
        )
        .unwrap();
    let value = response(child.wait_with_output().unwrap());
    assert_eq!(value["data"]["freshness"]["latest_satisfied"], true);
    assert_eq!(value["data"]["freshness"]["coverage"], "complete");
    assert_eq!(value["data"]["freshness"]["reason"], "verified");
    assert_ne!(value["data"]["freshness"]["update_state"], "unknown");
    let ordinary = response(f.run(&["search", "permitted"]));
    assert_eq!(ordinary["data"]["freshness"]["latest_requested"], false);
    assert_eq!(ordinary["data"]["freshness"]["latest_satisfied"], false);
    assert_eq!(ordinary["data"]["freshness"]["coverage"], "complete");
    assert_eq!(ordinary["data"]["freshness"]["reason"], "as_of_verified");
    assert_eq!(ordinary["data"]["freshness"]["contributing_sources"], 1);
    assert_eq!(ordinary["data"]["freshness"]["pending_sources"], 0);
    assert_ne!(ordinary["data"]["freshness"]["update_state"], "unknown");
    assert_eq!(
        value["data"]["snapshot"]["generation"],
        committed.receipt.committed_generation.unwrap()
    );
    assert_eq!(
        value["data"]["provenance"][0]["revision_digest"],
        observation.revision_digest
    );
    assert!(!value.to_string().contains("POST_ADMISSION_RECEIPT"));
}

struct LatestChild(Option<Child>);
impl Drop for LatestChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn only_latest_barrier(f: &Fixture, end: Instant) -> LatestBarrier {
    let conn = rusqlite::Connection::open_with_flags(
        SqliteControlStore::path(&f.root),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM barriers", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1,
        "one CLI request must admit exactly one barrier"
    );
    let identifier: String = conn
        .query_row("SELECT barrier_id FROM barriers", [], |row| row.get(0))
        .unwrap();
    f.control
        .with_runtime_deadline(end, || f.control.barrier(&id(&identifier)))
        .unwrap()
}

fn assert_same_latest_admission(before: &LatestBarrier, after: &LatestBarrier) {
    assert_eq!(after.id, before.id);
    assert_eq!(after.policy_epoch, before.policy_epoch);
    assert_eq!(after.admission_control_seq, before.admission_control_seq);
    assert_eq!(after.required_cycle_seq, before.required_cycle_seq);
    assert_eq!(after.requested_wait_ms, before.requested_wait_ms);
    assert_eq!(after.admitted_at_ms, before.admitted_at_ms);
    assert_eq!(after.selections, before.selections);
}

fn assert_latest_still_waiting(child: &mut Child, duration: Duration) {
    let end = Instant::now() + duration;
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "latest returned before its catalog proof was published"
        );
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10).min(remaining));
    }
}

fn await_latest_exit(child: &mut Child, end: Instant) {
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < end,
            "latest child did not exit within its bound"
        );
        std::thread::sleep(
            Duration::from_millis(10).min(end.saturating_duration_since(Instant::now())),
        );
    }
}

fn latest_with_worker_advisory(
    state: UpdateState,
    wait_ms: u32,
    release_owner: bool,
    action: impl FnOnce(
        &Fixture,
        &ManagedStore,
        &agent_session_grep_adapters_sqlite::control::LockedWorkerAuthority<'_>,
        &ObservationCycle,
        &mut Child,
        Instant,
    ),
) -> Output {
    let f = Fixture::new(1, "transient latest original needle");
    // Preparation gets its own end; the actual CLI retains its usual budget.
    let prepare_end = Instant::now() + Duration::from_secs(20);
    let guard = lock(&f.root, LockKind::Background);
    let worker = f.control.bind_worker(&guard, id("private-boot")).unwrap();
    let store = f
        .control
        .with_runtime_deadline(prepare_end, || {
            ManagedStore::open_for_write(&f.db, &f.control)
        })
        .unwrap();
    f.control
        .with_runtime_deadline(prepare_end, || {
            store.reconcile_progress(&f.control, &worker)
        })
        .unwrap();
    let next = f
        .control
        .with_runtime_deadline(prepare_end, || f.control.background_status())
        .unwrap()
        .next_cycle_seq;
    let wait = wait_ms.to_string();
    let mut child = LatestChild(Some(f.spawn(&[
        "search",
        "needle",
        "--latest",
        "--max-wait-ms",
        &wait,
    ])));
    let queued = f.await_queued_cycle(child.0.as_mut().unwrap(), next);
    let admitted = only_latest_barrier(&f, prepare_end);
    assert_eq!(admitted.required_cycle_seq, queued.token.cycle_seq);
    assert_eq!(admitted.requested_wait_ms, wait_ms);
    let cycle = f
        .control
        .with_runtime_deadline(prepare_end, || {
            f.control
                .start_cycle(current(&f.control), &worker, next, 10)
        })
        .unwrap()
        .value;
    assert!(cycle.started_control_seq.unwrap() > admitted.admission_control_seq);
    store
        .begin_discovery_with_deadline(
            &f.control,
            &worker,
            &cycle,
            &cycle.selections[0].selection,
            prepare_end,
        )
        .unwrap();
    let error = match state {
        UpdateState::Busy => BackgroundFailure::Busy,
        UpdateState::Deferred => BackgroundFailure::Deferred,
        _ => panic!("expected a transient worker advisory"),
    };
    f.control
        .with_runtime_deadline(prepare_end, || {
            f.control
                .heartbeat_worker(current(&f.control), &worker, state, Some(error), 12)
        })
        .unwrap();
    let advisory = only_latest_barrier(&f, prepare_end);
    assert_eq!(advisory.state, BarrierState::Blocked);
    assert_eq!(advisory.error, Some(error));
    assert_same_latest_admission(&admitted, &advisory);
    let persisted = f
        .control
        .with_runtime_deadline(prepare_end, || f.control.persisted_barrier(&admitted.id))
        .unwrap();
    assert_eq!(persisted.state, BarrierState::Pending);
    assert_eq!(persisted.error, None);
    assert_same_latest_admission(&admitted, &persisted);
    action(
        &f,
        &store,
        &worker,
        &cycle,
        child.0.as_mut().unwrap(),
        prepare_end,
    );
    let output = if release_owner {
        // Leave the advisory heartbeat untouched: only the real OS owner goes.
        drop(worker);
        drop(guard);
        await_latest_exit(
            child.0.as_mut().unwrap(),
            Instant::now() + Duration::from_secs(3),
        );
        child.0.take().unwrap().wait_with_output().unwrap()
    } else {
        await_latest_exit(child.0.as_mut().unwrap(), prepare_end);
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        worker.validate().unwrap();
        output
    };
    assert_same_latest_admission(&admitted, &only_latest_barrier(&f, prepare_end));
    let after = f
        .control
        .with_runtime_deadline(prepare_end, || f.control.background_status())
        .unwrap();
    assert_eq!(after.next_cycle_seq.get(), next.get() + 1);
    assert_eq!(after.worker.boot_id, Some(id("private-boot")));
    if release_owner {
        assert_eq!(after.worker.state, state);
    }
    output
}

fn latest_publishes_through_worker_advisory(state: UpdateState) {
    let output =
        latest_with_worker_advisory(state, 5000, false, |f, store, worker, cycle, child, end| {
            assert_latest_still_waiting(child, Duration::from_millis(600));
            f.control
                .with_runtime_deadline(end, || {
                    f.control.heartbeat_worker(
                        current(&f.control),
                        worker,
                        UpdateState::Running,
                        None,
                        13,
                    )
                })
                .unwrap();
            // A Running heartbeat and then a source receipt still cannot
            // substitute for discovery proof under the admitted token.
            assert_latest_still_waiting(child, Duration::from_millis(100));
            let mut observation = f.observation.clone();
            observation.cycle_seq = cycle.token.cycle_seq.get();
            observation.started_control_seq = cycle.started_control_seq.unwrap().get();
            observation.policy_epoch = cycle.policy_epoch.get();
            observation.revision_id = RevisionId::parse("transient-latest-receipt").unwrap();
            observation.observed_at_ms = 14;
            observation.committed_at_ms = 15;
            let published = f
                .control
                .with_runtime_deadline(end, || {
                    store.commit_source(&f.control, worker, &f.batch, &observation)
                })
                .unwrap();
            assert!(published.receipt.published);
            assert_latest_still_waiting(child, Duration::from_millis(100));
            store
                .commit_discovery_with_deadline(
                    &f.control,
                    worker,
                    cycle,
                    &cycle.selections[0].selection,
                    std::slice::from_ref(&observation.binding.source_id),
                    end,
                )
                .unwrap();
        });
    let value = response(output);
    // Search retains its existing native-resume capability warning. Freshness
    // and original evidence must still succeed under the same admitted barrier.
    assert_eq!(value["outcome"], "partial");
    assert_eq!(
        value["warnings"],
        json!(["resume_availability_unavailable"])
    );
    assert_eq!(value["data"]["freshness"]["latest_satisfied"], true);
    assert_eq!(value["data"]["freshness"]["coverage"], "complete");
    assert_eq!(value["data"]["freshness"]["reason"], "verified");
    assert_eq!(value["data"]["freshness"]["latest_requested"], true);
    assert_eq!(value["data"]["freshness"]["pending_sources"], 0);
    assert_eq!(value["data"]["freshness"]["failed_sources"], 0);
    assert_eq!(value["data"]["truncation"]["truncated"], false);
    assert!(
        value
            .to_string()
            .contains("transient latest original needle")
    );
}

#[test]
fn latest_waits_through_live_worker_busy_until_same_cycle_catalog_publication() {
    latest_publishes_through_worker_advisory(UpdateState::Busy);
}

#[test]
fn latest_waits_through_live_worker_deferred_until_same_cycle_catalog_publication() {
    latest_publishes_through_worker_advisory(UpdateState::Deferred);
}

#[test]
fn latest_pause_after_transient_advisory_remains_terminal() {
    for state in [UpdateState::Busy, UpdateState::Deferred] {
        let output =
            latest_with_worker_advisory(state, 5000, false, |f, _, worker, _, child, end| {
                assert_latest_still_waiting(child, Duration::from_millis(300));
                f.control
                    .with_runtime_deadline(end, || {
                        f.control
                            .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
                    })
                    .unwrap();
                let paused_seq = f
                    .control
                    .with_runtime_deadline(end, || Ok(current(&f.control)))
                    .unwrap();
                await_latest_exit(child, Instant::now() + Duration::from_secs(3));
                let status = f
                    .control
                    .with_runtime_deadline(end, || f.control.status())
                    .unwrap();
                assert_eq!(status.desired_updates, DesiredUpdates::Paused);
                assert_eq!(status.policy.control_seq, paused_seq);
                worker.validate().unwrap();
            });
        let value = response(output);
        assert_eq!(value["outcome"], "partial");
        assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
        assert_eq!(value["data"]["freshness"]["reason"], "paused");
    }
}

#[test]
fn latest_offline_after_transient_advisory_remains_terminal() {
    for state in [UpdateState::Busy, UpdateState::Deferred] {
        let output =
            latest_with_worker_advisory(state, 5000, false, |f, _, worker, _, child, end| {
                assert_latest_still_waiting(child, Duration::from_millis(300));
                f.control
                    .with_runtime_deadline(end, || {
                        f.control.stop_worker(current(&f.control), worker, 13)
                    })
                    .unwrap();
                await_latest_exit(child, Instant::now() + Duration::from_secs(3));
            });
        let value = response(output);
        assert_eq!(value["outcome"], "partial");
        assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
        assert_eq!(value["data"]["freshness"]["reason"], "offline");
    }
}

#[test]
fn latest_hard_worker_error_is_not_retried_as_a_transient_advisory() {
    let output = latest_with_worker_advisory(
        UpdateState::Busy,
        5000,
        false,
        |f, _, worker, _, child, end| {
            assert_latest_still_waiting(child, Duration::from_millis(300));
            f.control
                .with_runtime_deadline(end, || {
                    f.control.heartbeat_worker(
                        current(&f.control),
                        worker,
                        UpdateState::Busy,
                        Some(BackgroundFailure::Failed),
                        13,
                    )
                })
                .unwrap();
            await_latest_exit(child, Instant::now() + Duration::from_secs(3));
        },
    );
    let value = response(output);
    assert_eq!(value["outcome"], "partial");
    assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
    assert_eq!(value["data"]["freshness"]["reason"], "failed");
}

#[test]
fn latest_missing_os_owner_after_transient_advisory_returns_offline() {
    for state in [UpdateState::Busy, UpdateState::Deferred] {
        let output = latest_with_worker_advisory(state, 5000, true, |_, _, _, _, child, _| {
            assert_latest_still_waiting(child, Duration::from_millis(300));
        });
        let value = response(output);
        assert_eq!(value["outcome"], "partial");
        assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
        assert_eq!(value["data"]["freshness"]["reason"], "offline");
    }
}

#[test]
fn latest_transient_advisory_expires_without_renewing_its_original_wait() {
    for (state, reason) in [
        (UpdateState::Busy, "busy"),
        (UpdateState::Deferred, "deferred"),
    ] {
        let output = latest_with_worker_advisory(state, 5000, false, |_, _, _, _, child, _| {
            assert_latest_still_waiting(child, Duration::from_millis(300));
        });
        let value = response(output);
        assert_eq!(value["outcome"], "partial");
        assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
        assert_eq!(value["data"]["freshness"]["reason"], reason);
        assert!(value["meta"]["duration_ms"].as_u64().unwrap() >= 5000);
        assert!(value["meta"]["duration_ms"].as_u64().unwrap() < 10_000);
        assert!(
            value
                .to_string()
                .contains("transient latest original needle")
        );
    }
}

/// Raw stored admission rows, read beside the typed control API.
fn stored_latest_rows(f: &Fixture, barrier: &LatestBarrier) -> Vec<Vec<rusqlite::types::Value>> {
    let conn = rusqlite::Connection::open_with_flags(
        SqliteControlStore::path(&f.root),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let barrier_id = rusqlite::types::Value::Text(barrier.id.as_str().into());
    let cycle_seq = rusqlite::types::Value::Integer(barrier.required_cycle_seq.get());
    let mut rows = Vec::new();
    for (query, key) in [
        ("SELECT * FROM barriers WHERE barrier_id=?1", &barrier_id),
        (
            "SELECT * FROM barrier_selections WHERE barrier_id=?1 ORDER BY selection_id",
            &barrier_id,
        ),
        ("SELECT * FROM cycles WHERE cycle_seq=?1", &cycle_seq),
    ] {
        let mut statement = conn.prepare(query).unwrap();
        let width = statement.column_count();
        let mut found = statement.query([key]).unwrap();
        while let Some(row) = found.next().unwrap() {
            rows.push(
                (0..width)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index).unwrap())
                    .collect(),
            );
        }
    }
    rows
}

#[test]
fn latest_restart_advisory_never_masks_a_stored_offline_barrier() {
    // Each advisory runs twice: a poll that lands between the three commits
    // sees the unmasked Offline/Idle row and stops for the right reason anyway.
    for (state, error) in [
        (UpdateState::Busy, BackgroundFailure::Busy),
        (UpdateState::Deferred, BackgroundFailure::Deferred),
        (UpdateState::Busy, BackgroundFailure::Busy),
        (UpdateState::Deferred, BackgroundFailure::Deferred),
    ] {
        let f = Fixture::new(1, "restarted latest original needle");
        let prepare_end = Instant::now() + Duration::from_secs(20);
        let guard = lock(&f.root, LockKind::Background);
        let original = f.control.bind_worker(&guard, id("private-boot")).unwrap();
        let store = f
            .control
            .with_runtime_deadline(prepare_end, || {
                ManagedStore::open_for_write(&f.db, &f.control)
            })
            .unwrap();
        f.control
            .with_runtime_deadline(prepare_end, || {
                store.reconcile_progress(&f.control, &original)
            })
            .unwrap();
        drop(store);
        let next = f
            .control
            .with_runtime_deadline(prepare_end, || f.control.background_status())
            .unwrap()
            .next_cycle_seq;
        let mut child = LatestChild(Some(f.spawn(&[
            "search",
            "needle",
            "--latest",
            "--max-wait-ms",
            "5000",
        ])));
        let queued = f.await_queued_cycle(child.0.as_mut().unwrap(), next);
        let admitted = only_latest_barrier(&f, prepare_end);
        assert_eq!(admitted.required_cycle_seq, queued.token.cycle_seq);
        assert_eq!(admitted.state, BarrierState::Pending);
        assert_latest_still_waiting(child.0.as_mut().unwrap(), Duration::from_millis(300));
        // The original worker stops, then a new boot under the same Running
        // policy reports an advisory while the request's barrier stays blocked.
        let replacement = f
            .control
            .bind_worker(&guard, id("replacement-boot"))
            .unwrap();
        f.control
            .with_runtime_deadline(prepare_end, || {
                let stopped = f.control.stop_worker(current(&f.control), &original, 13)?;
                let registered =
                    f.control
                        .register_worker(stopped.control_seq, &replacement, 2, 14)?;
                f.control.heartbeat_worker(
                    registered.control_seq,
                    &replacement,
                    state,
                    Some(error),
                    15,
                )
            })
            .unwrap();
        let masked = only_latest_barrier(&f, prepare_end);
        assert_same_latest_admission(&admitted, &masked);
        assert_eq!(masked.state, BarrierState::Blocked);
        assert_eq!(
            masked.error,
            Some(error),
            "the live advisory hides the stored row"
        );
        let stored = f
            .control
            .with_runtime_deadline(prepare_end, || f.control.persisted_barrier(&admitted.id))
            .unwrap();
        assert_same_latest_admission(&admitted, &stored);
        assert_eq!(stored.state, BarrierState::Blocked);
        assert_eq!(stored.error, Some(BackgroundFailure::Offline));
        let rows = stored_latest_rows(&f, &admitted);
        let control_seq = current(&f.control);
        await_latest_exit(
            child.0.as_mut().unwrap(),
            Instant::now() + Duration::from_secs(3),
        );
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        // Returning offline is read-only: no row, sequence or worker changes.
        assert_eq!(stored_latest_rows(&f, &admitted), rows);
        assert_eq!(current(&f.control), control_seq);
        assert_same_latest_admission(&admitted, &only_latest_barrier(&f, prepare_end));
        let after = f
            .control
            .with_runtime_deadline(prepare_end, || f.control.background_status())
            .unwrap();
        assert_eq!(after.worker.boot_id, Some(id("replacement-boot")));
        assert_eq!(after.worker.state, state);
        replacement.validate().unwrap();
        let value = response(output);
        assert_eq!(value["outcome"], "partial");
        assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
        assert_eq!(value["data"]["freshness"]["reason"], "offline");
        assert!(value["meta"]["duration_ms"].as_u64().unwrap() < 5000);
    }
}

#[test]
fn latest_timeout_offline_and_pause_never_spawn_or_resume_a_worker() {
    let f = Fixture::new(1, "old permitted evidence");
    let offline = response(f.run(&["search", "permitted", "--latest", "--max-wait-ms", "200"]));
    assert_eq!(offline["data"]["freshness"]["latest_satisfied"], false);
    assert_eq!(offline["data"]["freshness"]["reason"], "offline");
    let guard = lock(&f.root, LockKind::Background);
    let before = f.control.background_status().unwrap();
    let value = response(f.run(&["search", "permitted", "--latest", "--max-wait-ms", "0"]));
    assert_eq!(value["data"]["freshness"]["reason"], "timeout");
    assert_eq!(value["outcome"], "partial");
    assert_eq!(
        f.control.background_status().unwrap().worker.boot_id,
        before.worker.boot_id
    );
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let paused = current(&f.control);
    let value = response(f.run(&["search", "permitted", "--latest", "--max-wait-ms", "1000"]));
    assert_eq!(value["data"]["freshness"]["reason"], "paused");
    assert_eq!(
        current(&f.control),
        paused,
        "pause must not mutate control or admit cycles"
    );
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    drop(guard);
}

#[test]
fn latest_provider_relevance_does_not_wait_for_an_unrelated_provider() {
    let f = Fixture::new(1, "provider scoped needle");
    f.control
        .add_selection(
            current(&f.control),
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Codex,
                    locator: CanonicalLocator::from_path(&f._temp.path().canonicalize().unwrap())
                        .unwrap(),
                    kind: RootKind::Root,
                },
                root_identity: Some(id("codex-root")),
                now_ms: 8,
            },
        )
        .unwrap();
    let guard = lock(&f.root, LockKind::Background);
    let worker = f.control.bind_worker(&guard, id("private-boot")).unwrap();
    let next = f.control.background_status().unwrap().next_cycle_seq;
    let mut child = f.spawn(&[
        "search",
        "needle",
        "--provider",
        "claude-code",
        "--latest",
        "--max-wait-ms",
        "4000",
    ]);
    let queued = f.await_queued_cycle(&mut child, next);
    assert_eq!(queued.selections.len(), 1);
    assert_eq!(queued.selections[0].selection.selection_id, f.selection);
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let value = response(child.wait_with_output().unwrap());
    assert_eq!(value["data"]["freshness"]["reason"], "paused");
    assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
    worker.validate().unwrap();
}

#[test]
fn human_jsonl_and_explicit_resume_use_the_same_safe_evidence() {
    let f = Fixture::new(1, "ordinary safe evidence");
    let human = Command::new(BIN)
        .arg("--db")
        .arg(&f.db)
        .args(["search", "ordinary"])
        .output()
        .unwrap();
    assert!(matches!(human.status.code(), Some(0 | 10)));
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("ordinary safe evidence"));
    assert!(!human.contains("PRIVATE_SOURCE_SENTINEL"));
    let jsonl = Command::new(BIN)
        .args(["--output", "jsonl", "--db"])
        .arg(&f.db)
        .args(["search", "ordinary"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&jsonl.stdout).lines().count(), 1);
    response(jsonl);
    let resume = response(f.run(&["get-session-resume", f.session.as_str()]));
    assert!(resume.to_string().contains("NATIVE_RESUME_SENTINEL"));
    assert!(
        !resume["data"]["provenance"]
            .to_string()
            .contains("NATIVE_RESUME_SENTINEL")
    );
}

#[test]
fn mcp_final_frame_counts_rpc_id_duplicate_payload_and_redaction() {
    let f = Fixture::new(
        12,
        &format!(
            "needle {} sk-ant-api03-1234567890abcdef",
            "quoted \\\"text\\\" ".repeat(50)
        ),
    );
    let rpc_id = "id\\\"".repeat(32);
    let calls = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":rpc_id,"method":"tools/call","params":{"name":"search_sessions","arguments":{"query":"needle","max_bytes":8192}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_session_context","arguments":{"session_id":f.session.as_str(),"providers":["codex"]}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_sessions","arguments":{"repo":"example.test/other/project"}}}),
    ];
    let mut child = Command::new(BIN)
        .arg("--db")
        .arg(&f.db)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for call in calls {
        writeln!(input, "{call}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let wire = String::from_utf8(output.stdout).unwrap();
    let lines = wire.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "{wire}");
    assert!(lines[1].len() < 8192, "newline also counts");
    let result: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(result["id"], rpc_id);
    assert_eq!(result["result"]["isError"], false);
    let payload = &result["result"]["structuredContent"];
    assert_eq!(
        serde_json::from_str::<Value>(result["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap(),
        *payload
    );
    assert_eq!(payload["outcome"], "partial");
    assert!(
        payload["data"]["hits"]
            .as_array()
            .is_some_and(|h| !h.is_empty() && h.len() <= 5)
    );
    assert!(!wire.contains("sk-ant-api03-1234567890abcdef"));
    assert!(!wire.contains("PRIVATE_SOURCE_SENTINEL"));
    assert!(!wire.contains("PRIVATE_REVISION_ID"));
    let restricted: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(
        restricted["result"]["structuredContent"]["error"]["canonical_code"],
        "not_found"
    );
    let listed: Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(
        listed["result"]["structuredContent"]["data"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn continuation_keeps_complete_ranked_window_through_append_and_page_budget_changes() {
    let f = Fixture::new(18, &format!("needle {}", "safe words ".repeat(60)));
    let first = response(f.run(&["search", "needle", "--max-items", "5"]));
    let mut cursor = first["page"]["next_cursor"]
        .as_str()
        .expect("complete window cached")
        .to_owned();
    let snapshot = first["data"]["snapshot"].clone();
    let mut hits = first["data"]["hits"].as_array().unwrap().clone();
    let before = response(f.run(&["search", "needle", "--cursor", &cursor, "--max-items", "2"]));
    f.commit_extra_source();
    let after = response(f.run(&["search", "needle", "--cursor", &cursor, "--max-items", "2"]));
    assert_eq!(before["data"]["hits"], after["data"]["hits"]);
    assert_eq!(before["data"]["provenance"], after["data"]["provenance"]);
    assert_eq!(after["data"]["snapshot"], snapshot);
    let mut seen = std::collections::BTreeSet::new();
    for hit in &hits {
        assert!(seen.insert(hit["id"].as_str().unwrap().to_owned()));
    }
    for _ in 0..20 {
        let page = response(f.run(&[
            "search",
            "needle",
            "--cursor",
            &cursor,
            "--max-items",
            "5",
            "--max-bytes",
            "4096",
        ]));
        assert_eq!(page["data"]["snapshot"], snapshot);
        let next = page["data"]["hits"].as_array().unwrap();
        assert!(!next.is_empty());
        for hit in next {
            assert!(
                seen.insert(hit["id"].as_str().unwrap().to_owned()),
                "duplicate/skip offset"
            );
            assert_ne!(hit["id"], "msg_v1_extra-message");
        }
        hits.extend(next.clone());
        match page["page"]["next_cursor"].as_str() {
            Some(next) => cursor = next.into(),
            None => break,
        }
    }
    let mut expected = (0..18)
        .map(|n| format!("msg_v1_message-{n}"))
        .collect::<std::collections::BTreeSet<_>>();
    expected.insert(f.session.as_str().to_owned());
    assert_eq!(
        seen, expected,
        "all original Message and Session candidates, no post-append candidates"
    );
    assert_eq!(
        hits.len(),
        expected.len(),
        "full window without duplicated candidates"
    );
    let metadata = hits
        .iter()
        .find(|hit| hit["id"] == f.session.as_str())
        .unwrap();
    assert!(metadata["text"].is_null());
    assert_eq!(
        metadata["why_matched"],
        json!(["session_metadata", "session_first_user"])
    );
    assert!(
        hits.windows(2)
            .all(|h| h[0]["score"].as_f64().unwrap() >= h[1]["score"].as_f64().unwrap())
    );
    let fresh = response(f.run(&["search", "needle", "--max-items", "1"]));
    assert_ne!(
        fresh["data"]["snapshot"]["generation"],
        snapshot["generation"]
    );
}

#[test]
fn continuation_rewrite_revoke_wrong_query_and_cache_busy_fail_honestly() {
    let f = Fixture::new(10, "needle cached original");
    let first = response(f.run(&["search", "needle", "--max-items", "2"]));
    let cursor = first["page"]["next_cursor"].as_str().unwrap();
    for args in [
        vec!["search", "different", "--cursor", cursor],
        vec![
            "search",
            "needle",
            "--cursor",
            cursor,
            "--provider",
            "codex",
        ],
        vec!["search", "needle", "--cursor", cursor, "--latest"],
    ] {
        let result = f.run(&args);
        assert_eq!(result.status.code(), Some(2));
        let result: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(result["error"]["code"], "cursor_invalid");
    }
    let cache = rusqlite::Connection::open(f.root.join("continuations.db")).unwrap();
    cache.execute_batch("BEGIN IMMEDIATE").unwrap();
    let one_shot = response(f.run(&["search", "needle", "--max-items", "2"]));
    assert!(one_shot["page"]["next_cursor"].is_null());
    assert!(
        one_shot["warnings"]
            .as_array()
            .unwrap()
            .contains(&json!("continuation_unavailable"))
    );
    let busy = f.run(&["search", "needle", "--cursor", cursor]);
    assert_eq!(
        serde_json::from_slice::<Value>(&busy.stdout).unwrap()["error"]["code"],
        "cursor_expired"
    );
    cache.execute_batch("ROLLBACK").unwrap();
    drop(cache);
    f.rewrite_source();
    let rewritten = f.run(&["search", "needle", "--cursor", cursor]);
    assert_eq!(
        serde_json::from_slice::<Value>(&rewritten.stdout).unwrap()["error"]["code"],
        "cursor_expired"
    );
    let current = response(f.run(&["search", "needle", "--max-items", "2"]));
    let cursor = current["page"]["next_cursor"].as_str().unwrap();
    f.revoke();
    let revoked = f.run(&["search", "needle", "--cursor", cursor]);
    assert_eq!(
        serde_json::from_slice::<Value>(&revoked.stdout).unwrap()["error"]["code"],
        "cursor_expired"
    );
    assert!(!String::from_utf8_lossy(&revoked.stdout).contains("cached original"));
}

#[test]
fn list_continuation_keeps_typed_preview_and_no_legacy_cursor() {
    let f = Fixture::new(10, "needle list evidence");
    let first = response(f.run(&["list", "2"]));
    let cursor = first["page"]["next_cursor"].as_str().expect("list cache");
    let next = response(f.run(&["list", "2", "--cursor", cursor]));
    assert_eq!(first["data"]["snapshot"], next["data"]["snapshot"]);
    let ids = first["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].clone())
        .collect::<Vec<_>>();
    assert!(
        next["data"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| !ids.contains(&e["id"]))
    );
    let wrong = f.run(&["list", "2", "--sessions-only", "--cursor", cursor]);
    assert_eq!(
        serde_json::from_slice::<Value>(&wrong.stdout).unwrap()["error"]["code"],
        "cursor_invalid"
    );
}

// F1/F2 regressions use the same real process and source-proof fixture above.
// These helpers never manufacture retained receipts or modify production SQL.
fn acknowledge_complete_cycle(
    f: &Fixture,
    store: &ManagedStore,
    worker: &agent_session_grep_adapters_sqlite::control::LockedWorkerAuthority<'_>,
    cycle: &ObservationCycle,
    sources: &[SourceId],
    now_ms: i64,
) {
    store
        .commit_discovery(
            &f.control,
            worker,
            cycle,
            &cycle.selections[0].selection,
            sources,
            now_ms,
        )
        .unwrap();
    store.reconcile_progress(&f.control, worker).unwrap();
    f.control
        .acknowledge_discovery(
            current(&f.control),
            worker,
            DiscoveryAcknowledgement {
                token: cycle.token.clone(),
                selection: cycle.selections[0].selection.clone(),
                complete: true,
                discovered_count: sources.len() as u64,
                observed_count: sources.len() as u64,
                committed_count: sources.len() as u64,
                error: None,
            },
        )
        .unwrap();
    f.control
        .finish_cycle(
            current(&f.control),
            worker,
            cycle.token.cycle_seq,
            CycleFinish::Committed,
            now_ms,
        )
        .unwrap();
    f.control
        .heartbeat_worker(current(&f.control), worker, UpdateState::Idle, None, now_ms)
        .unwrap();
}
fn complete_fixture_observation(f: &Fixture, extra: bool) {
    let guard = lock(&f.root, LockKind::Background);
    let worker = f.control.bind_worker(&guard, id("private-boot")).unwrap();
    let store = ManagedStore::open_for_write(&f.db, &f.control).unwrap();
    // Initial catalog-summary admission invalidates the old fixture cycle.
    // Establish a fresh real cycle rather than adopting its aborted token.
    store.reconcile_progress(&f.control, &worker).unwrap();
    let cycle = next_observing_cycle(f, &worker, 10);
    let mut observed = f.observation.clone();
    observed.cycle_seq = cycle.token.cycle_seq.get();
    observed.started_control_seq = cycle.started_control_seq.unwrap().get();
    observed.policy_epoch = cycle.policy_epoch.get();
    observed.revision_id = RevisionId::parse("synthetic-current-primary-receipt").unwrap();
    observed.observed_at_ms = 11;
    observed.committed_at_ms = 12;
    store
        .commit_source(&f.control, &worker, &f.batch, &observed)
        .unwrap();
    let mut sources = vec![observed.binding.source_id.clone()];
    if extra {
        let (batch, mut observed) = f.extra_source_batch();
        observed.cycle_seq = cycle.token.cycle_seq.get();
        observed.started_control_seq = cycle.started_control_seq.unwrap().get();
        observed.policy_epoch = cycle.policy_epoch.get();
        observed.revision_id = RevisionId::parse("synthetic-current-extra-receipt").unwrap();
        observed.observed_at_ms = 11;
        observed.committed_at_ms = 12;
        store
            .commit_source(&f.control, &worker, &batch, &observed)
            .unwrap();
        sources.push(observed.binding.source_id);
    }
    acknowledge_complete_cycle(f, &store, &worker, &cycle, &sources, 13);
}
fn next_observing_cycle(
    f: &Fixture,
    worker: &agent_session_grep_adapters_sqlite::control::LockedWorkerAuthority<'_>,
    now_ms: i64,
) -> ObservationCycle {
    let status = f.control.status().unwrap();
    let selections = status
        .policy
        .selections
        .iter()
        .filter(|s| s.enabled)
        .map(|s| SelectionRevision {
            selection_id: s.id.clone(),
            revision: s.revision,
            root_identity: s.root_identity.clone().unwrap(),
        })
        .collect();
    let CycleAdmission::Queued(cycle) = f
        .control
        .queue_cycle(current(&f.control), selections)
        .unwrap()
        .value
    else {
        panic!("synthetic cycle was blocked");
    };
    f.control
        .start_cycle(current(&f.control), worker, cycle.token.cycle_seq, now_ms)
        .unwrap()
        .value
}

struct EvidenceMcpClient {
    child: Child,
    input: Option<ChildStdin>,
    frames: Receiver<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
    next_id: u64,
}
impl EvidenceMcpClient {
    fn connect(db: &Path) -> Self {
        let mut child = Command::new(BIN)
            .arg("--db")
            .arg(db)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = child.stdout.take().unwrap();
        let (sender, frames) = channel();
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if sender.send(line).is_err() => break,
                    Ok(_) => {}
                }
            }
        });
        let mut client = Self {
            child,
            input,
            frames,
            reader: Some(reader),
            next_id: 1,
        };
        let frame=client.request("initialize",json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic-restore","version":"1"}}));
        assert_eq!(frame["result"]["protocolVersion"], "2025-06-18");
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client
    }
    fn send(&mut self, frame: Value) {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{frame}").unwrap();
        input.flush().unwrap();
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        let request_id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":request_id,"method":method,"params":params}));
        let bytes = self
            .frames
            .recv_timeout(Duration::from_secs(10))
            .expect("bounded actual MCP frame");
        assert!(
            bytes.len() <= 8192,
            "complete MCP frame exceeded its advertised default"
        );
        let frame: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(frame["id"], request_id);
        frame
    }
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        let frame = self.request("tools/call", json!({"name":name,"arguments":arguments}));
        assert_eq!(frame["result"]["isError"], false, "{frame}");
        let result = frame["result"]["structuredContent"].clone();
        assert_eq!(
            serde_json::from_str::<Value>(frame["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap(),
            result
        );
        result
    }
}
impl Drop for EvidenceMcpClient {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn restore_verified_backup_while_paused(f: &Fixture) -> ControlId {
    let end = Instant::now() + Duration::from_secs(10);
    let owner = id("synthetic-restore-owner");
    let backup_id = id("synthetic-restore-backup");
    let incarnation = id("synthetic-restored-incarnation");
    let prefix = f._temp.path().join("synthetic-install-prefix");
    std::fs::create_dir(&prefix).unwrap();
    let installation_guard = lock(
        &prefix,
        LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
    );
    {
        let guard = lock(&f.root, LockKind::PolicyOwner);
        let bound = f.control.bind_control_root(&guard).unwrap();
        f.control
            .record_verified_installation_prefix(&prefix, &installation_guard, &bound, end)
            .unwrap();
    }
    let installation = f
        .control
        .bind_installation(&prefix, &installation_guard)
        .unwrap();
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    {
        let guard = lock(&f.root, LockKind::PolicyOwner);
        let bound = f.control.bind_control_root(&guard).unwrap();
        f.control
            .begin_maintenance(
                current(&f.control),
                &owner,
                &bound,
                &installation,
                MaintenanceFence {
                    state: MaintenanceState::Updating,
                    owner: Some(owner.clone()),
                    phase: Some(MaintenancePhase::Quiescing),
                },
            )
            .unwrap();
    }
    let mut catalog =
        MaintenanceCatalog::open_authorized(&f.control, &installation, &owner, &f.db, end).unwrap();
    let BackupOutcome::Created(metadata) = catalog
        .create_backup(
            &f.control,
            &installation,
            &owner,
            &backup_id,
            BackupPurpose::BetaRollback,
            20,
            end,
        )
        .unwrap()
    else {
        panic!("synthetic fully classified allowed catalog backup was refused");
    };
    assert_eq!(metadata.catalog_incarnation, id("private-incarnation"));
    let verified = verify_backup_until(&f.control, &backup_id, end).unwrap();
    assert_eq!(verified.metadata().digest, metadata.digest);
    assert_eq!(verified.coverage().len(), 1);
    let side = f.root.join("synthetic-restore-prepared.db");
    let RestoreOutcome::Prepared(prepared) = prepare_restore(
        &f.control,
        &installation,
        &owner,
        &backup_id,
        &incarnation,
        &side,
        end,
    )
    .unwrap() else {
        panic!("verified synthetic backup failed restore preparation");
    };
    assert_eq!(prepared.catalog_generation(), metadata.catalog_generation);
    assert_eq!(prepared.incarnation(), &incarnation);
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    // The maintenance capability publishes the verified owned side image,
    // preserves the displaced catalog as a registered backup, then records the
    // exact control consequences. A hand-renamed fixture cannot prove recovery.
    assert_eq!(
        apply_restore(
            &mut catalog,
            &f.control,
            &installation,
            &owner,
            &prepared,
            21,
            end
        )
        .unwrap(),
        incarnation
    );
    drop(catalog);
    let inventory =
        agent_session_grep_adapters_sqlite::managed_maintenance::inspect_restore_inventory(
            &f.control, &f.db, end,
        )
        .unwrap();
    assert!(!inventory.incomplete());
    assert!(inventory.staged_images().is_empty());
    assert_eq!(inventory.receipts().len(), 1);
    assert!(inventory.receipts()[0].complete());
    {
        let guard = lock(&f.root, LockKind::PolicyOwner);
        let bound = f.control.bind_control_root(&guard).unwrap();
        f.control
            .clear_maintenance(current(&f.control), &owner, &bound, &installation)
            .unwrap();
    }
    let status = f.control.status().unwrap();
    assert_eq!(status.catalog_incarnation, Some(incarnation.clone()));
    assert_eq!(status.desired_updates, DesiredUpdates::Paused);
    assert_eq!(status.policy.maintenance.state, MaintenanceState::Idle);
    incarnation
}
fn assert_retained_paused(value: &Value, original: &str, latest: bool) {
    assert_eq!(value["outcome"], "partial");
    assert!(
        value["data"].to_string().contains(original),
        "original allowed text missing: {value}"
    );
    assert!(
        value["warnings"]
            .as_array()
            .unwrap()
            .contains(&json!("retained_evidence")),
        "{value}"
    );
    let freshness = &value["data"]["freshness"];
    assert_eq!(freshness["coverage"], "partial");
    assert_eq!(freshness["update_state"], "paused");
    assert_eq!(freshness["latest_requested"], latest);
    assert_eq!(freshness["latest_satisfied"], false);
    assert_eq!(freshness["verified_sources"], 0);
    assert_eq!(freshness["contributing_sources"], 1);
    assert_eq!(freshness["pending_sources"], 1);
    assert_eq!(freshness["last_verified_observation_at_ms"], Value::Null);
    assert_eq!(freshness["complete_scopes"], 0);
}

#[test]
fn f1_verified_restore_keeps_paused_original_evidence_in_cli_human_and_existing_mcp_until_reobserved()
 {
    let original = "synthetic restored original allowed text";
    let f = Fixture::new(1, original);
    complete_fixture_observation(&f, false);
    let before = response(f.run(&["show", f.message.as_str()]));
    assert_eq!(before["data"]["freshness"]["verified_sources"], 1);
    let mut mcp = EvidenceMcpClient::connect(&f.db);
    let before_mcp = mcp.call(
        "get_message",
        json!({"message_id":f.message.as_str(),"session_id":f.session.as_str()}),
    );
    assert!(before_mcp["data"].to_string().contains(original));
    let incarnation = restore_verified_backup_while_paused(&f);
    let control_after_restore = current(&f.control);
    let ordinary = response(f.run(&["show", f.message.as_str()]));
    assert_retained_paused(&ordinary, original, false);
    let latest = response(f.run(&["show", f.message.as_str(), "--latest", "--max-wait-ms", "0"]));
    assert_retained_paused(&latest, original, true);
    let context = response(f.run(&["context", f.session.as_str()]));
    assert_retained_paused(&context, original, false);
    let human = Command::new(BIN)
        .arg("--db")
        .arg(&f.db)
        .args(["show", f.message.as_str()])
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(10));
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains(original));
    assert!(human.contains("warning: retained_evidence"));
    assert!(human.contains("freshness: paused (paused)"));
    let current_mcp = mcp.call(
        "get_message",
        json!({"message_id":f.message.as_str(),"session_id":f.session.as_str()}),
    );
    assert_retained_paused(&current_mcp, original, false);
    let latest_mcp=mcp.call("get_message",json!({"message_id":f.message.as_str(),"session_id":f.session.as_str(),"latest":true,"max_wait_ms":0}));
    assert_retained_paused(&latest_mcp, original, true);
    assert_eq!(
        current(&f.control),
        control_after_restore,
        "paused latest must not admit a new cycle"
    );
    for payload in [&ordinary, &latest, &context, &current_mcp, &latest_mcp] {
        let wire = payload.to_string();
        assert!(!wire.contains("private-incarnation"));
        assert!(!wire.contains("synthetic-restored-incarnation"));
        assert!(!wire.contains("PRIVATE_SOURCE_SENTINEL"));
    }
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Running)
        .unwrap();
    let guard = lock(&f.root, LockKind::Background);
    let worker = f
        .control
        .bind_worker(&guard, id("synthetic-reobservation-boot"))
        .unwrap();
    f.control
        .register_worker(current(&f.control), &worker, 1, 30)
        .unwrap();
    let store = ManagedStore::open_for_write(&f.db, &f.control).unwrap();
    assert_eq!(store.incarnation(), &incarnation);
    // A real restarted worker reconciles restored receipts before observation.
    store.reconcile_progress(&f.control, &worker).unwrap();
    let cycle = next_observing_cycle(&f, &worker, 31);
    let mut observation = f.observation.clone();
    observation.catalog_incarnation = incarnation.as_str().into();
    observation.worker_boot_id = worker.boot_id().as_str().into();
    observation.cycle_seq = cycle.token.cycle_seq.get();
    observation.started_control_seq = cycle.started_control_seq.unwrap().get();
    observation.policy_epoch = cycle.policy_epoch.get();
    observation.revision_id = RevisionId::parse("synthetic-reobserved-receipt").unwrap();
    observation.observed_at_ms = 32;
    observation.committed_at_ms = 33;
    store
        .commit_source(&f.control, &worker, &f.batch, &observation)
        .unwrap();
    acknowledge_complete_cycle(
        &f,
        &store,
        &worker,
        &cycle,
        std::slice::from_ref(&observation.binding.source_id),
        34,
    );
    drop(store);
    let reobserved = response(f.run(&["show", f.message.as_str()]));
    assert!(reobserved["data"].to_string().contains(original));
    assert_eq!(reobserved["data"]["freshness"]["verified_sources"], 1);
    assert_eq!(reobserved["data"]["freshness"]["pending_sources"], 0);
    assert_eq!(reobserved["data"]["freshness"]["coverage"], "complete");
    assert_eq!(
        reobserved["data"]["freshness"]["last_verified_observation_at_ms"],
        32
    );
    assert!(
        !reobserved["warnings"]
            .as_array()
            .unwrap()
            .contains(&json!("retained_evidence"))
    );
}

#[test]
fn f2_human_and_json_direct_evidence_hide_noncontributing_selected_source_failure() {
    let original = "synthetic sanitized contributing original";
    let f = Fixture::new(1, original);
    f.commit_extra_source();
    complete_fixture_observation(&f, true);
    let guard = lock(&f.root, LockKind::Background);
    let worker = f.control.bind_worker(&guard, id("private-boot")).unwrap();
    let store = ManagedStore::open_for_write(&f.db, &f.control).unwrap();
    let cycle = next_observing_cycle(&f, &worker, 20);
    store
        .begin_discovery(
            &f.control,
            &worker,
            &cycle,
            &cycle.selections[0].selection,
            20,
        )
        .unwrap();
    let mut failed = f.observation.clone();
    failed.binding.source_id = SourceId::parse("extra-source").unwrap();
    failed.binding.source_path = CanonicalLocator::from_path(&f._temp.path().join("extra.jsonl"))
        .unwrap()
        .as_str()
        .into();
    failed.revision_id = RevisionId::parse("synthetic-failed-extra-attempt").unwrap();
    failed.state = ObservationState::Incomplete;
    failed.cycle_seq = cycle.token.cycle_seq.get();
    failed.started_control_seq = cycle.started_control_seq.unwrap().get();
    failed.policy_epoch = cycle.policy_epoch.get();
    failed.observed_at_ms = 21;
    failed.committed_at_ms = 22;
    failed.repositories.clear();
    let mut batch = f.batch.clone();
    batch.source_path = failed.binding.source_path.clone();
    batch.entries.clear();
    batch.placements.clear();
    batch.edges.clear();
    batch.resume_claims.clear();
    batch.relation_complete = false;
    assert!(
        !store
            .commit_source(&f.control, &worker, &batch, &failed)
            .unwrap()
            .receipt
            .published
    );
    f.control
        .acknowledge_source(
            current(&f.control),
            &worker,
            SourceAcknowledgement {
                source_id: id("extra-source"),
                provider: SearchProvider::Claude,
                token: cycle.token.clone(),
                selection: cycle.selections[0].selection.clone(),
                attempted_at_ms: 21,
                coverage: Coverage::Partial,
                update_state: UpdateState::Failed,
                backfill_state: BackfillState::Pending,
                error: Some(BackgroundFailure::Failed),
                receipt: None,
                confirmation: None,
            },
        )
        .unwrap();
    f.control
        .heartbeat_worker(
            current(&f.control),
            &worker,
            UpdateState::Failed,
            Some(BackgroundFailure::Failed),
            22,
        )
        .unwrap();
    assert_eq!(
        f.control
            .source_progress(&id("extra-source"))
            .unwrap()
            .unwrap()
            .error,
        Some(BackgroundFailure::Failed)
    );
    assert_eq!(
        f.control.background_status().unwrap().worker.state,
        UpdateState::Failed
    );
    drop(store);
    let scoped = response(f.run(&["search", "contributing"]));
    assert_eq!(scoped["data"]["freshness"]["update_state"], "failed");
    for args in [
        vec!["show", f.message.as_str()],
        vec![
            "get-message",
            f.message.as_str(),
            "--session",
            f.session.as_str(),
        ],
        vec!["context", f.session.as_str()],
    ] {
        let robot = response(f.run(&args));
        let freshness = &robot["data"]["freshness"];
        assert_eq!(freshness["contributing_sources"], 1);
        assert_eq!(freshness["verified_sources"], 1);
        assert_eq!(freshness["pending_sources"], 0);
        assert_eq!(freshness["failed_sources"], 0);
        assert_eq!(freshness["update_state"], "running");
        assert_eq!(freshness["reason"], "discovery_pending");
        let human = Command::new(BIN)
            .arg("--db")
            .arg(&f.db)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            human.status.code(),
            Some(if robot["outcome"] == "partial" { 10 } else { 0 })
        );
        let stdout = String::from_utf8(human.stdout).unwrap();
        let stderr = String::from_utf8(human.stderr).unwrap();
        assert!(stdout.contains(original));
        let expected = format!(
            "freshness: {} ({})",
            freshness["update_state"].as_str().unwrap(),
            freshness["reason"].as_str().unwrap()
        );
        assert!(
            stdout.lines().any(|line| line == expected),
            "Human and JSON freshness diverged: {stdout}"
        );
        // The fixed freshness schema legitimately has failed_sources: 0.
        // Reject the actual failed state/diagnostic token, not that field name.
        for output in [&stdout, &stderr] {
            assert!(
                !output
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|word| word.eq_ignore_ascii_case("failed")),
                "noncontributing failure escaped: {output}"
            );
            assert!(!output.contains("extra-source"));
            assert!(!output.contains("synthetic-failed-extra-attempt"));
            assert!(!output.contains("PRIVATE_SOURCE_SENTINEL"));
            assert!(!output.contains("extra-message"));
        }
        for line in stdout
            .lines()
            .filter_map(|line| line.strip_prefix("freshness: "))
        {
            if line.starts_with('{') {
                assert_eq!(serde_json::from_str::<Value>(line).unwrap(), *freshness);
            }
        }
        assert!(
            !robot["warnings"]
                .as_array()
                .unwrap()
                .contains(&json!("failed"))
        );
        assert!(
            !robot["data"]["provenance"]
                .to_string()
                .contains("extra-source")
        );
    }
}

/// Synthetic shape of a long assistant session: (role, text bytes, quotes,
/// backslashes, tool activity). Tool-result turns carry the large, quote-heavy
/// text whose escaping dominates a rendered context frame. All text is
/// generated; no assistant history is used.
const REPLAY_SHAPE: [(&str, usize, usize, usize, bool); 12] = [
    ("user", 370, 0, 0, false),
    ("assistant", 131, 0, 0, false),
    ("assistant", 39, 0, 0, false),
    ("user", 2767, 384, 0, true),
    ("assistant", 81, 0, 0, false),
    ("user", 906, 34, 0, false),
    ("assistant", 45, 0, 0, false),
    ("assistant", 86, 0, 0, false),
    ("user", 5439, 388, 37, true),
    ("assistant", 679, 2, 0, false),
    ("assistant", 36, 0, 0, false),
    ("user", 1716, 170, 0, true),
];

/// Exactly `bytes` ASCII bytes of plain words with `quotes` double quotes and
/// `backslashes` backslashes spread through them. No redaction rule matches.
fn synthetic_text(seed: usize, bytes: usize, quotes: usize, backslashes: usize) -> String {
    const WORDS: [&str; 8] = [
        "alpha ", "bravo ", "carrot ", "delta ", "ember ", "fable ", "garden ", "harbor ",
    ];
    let mut text = WORDS
        .iter()
        .cycle()
        .skip(seed)
        .flat_map(|word| word.bytes())
        .take(bytes)
        .collect::<Vec<_>>();
    let specials = quotes + backslashes;
    for n in 0..specials {
        text[n * bytes / specials] = if n < quotes { b'"' } else { b'\\' };
    }
    String::from_utf8(text).unwrap()
}

struct Replay {
    session: StableId,
    document: StableId,
    messages: Vec<StableId>,
    placements: Vec<String>,
}

impl Fixture {
    /// Replace the seed source with the synthetic 12-message session: byte
    /// spans, one reply chain and three tool activities. Identifier lengths
    /// match the provider-native shape (36-character native suffixes).
    fn commit_replay(&self) -> Replay {
        let guard = lock(&self.root, LockKind::Background);
        let worker = self
            .control
            .bind_worker(&guard, id("private-boot"))
            .unwrap();
        let store = ManagedStore::open_for_write(&self.db, &self.control).unwrap();
        let session = entity(IdKind::Session, "00000000-0000-4000-8000-00000000c0de");
        let document = entity(IdKind::Document, "00000000-0000-4000-8000-00000000d0c5");
        let mut observation = self.observation.clone();
        observation.revision_id = RevisionId::parse("replay-receipt").unwrap();
        observation.repositories = vec![RepositoryClaim {
            session_id: session.clone(),
            slug: "example.test/team/project".into(),
        }];
        let mut batch = self.batch.clone();
        batch.entries = vec![
            (session.clone(), serde_json::to_vec(&json!({"documents":[document.as_str()],"title":"Synthetic replay session"})).unwrap(), String::new()),
            (document.clone(), serde_json::to_vec(&json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":observation.revision_digest,"len":1000000})).unwrap(), String::new()),
        ];
        batch.placements.clear();
        batch.edges.clear();
        batch.activities.clear();
        batch.resume_claims[0].session_id = session.as_str().into();
        let (mut messages, mut placements) = (Vec::new(), Vec::new());
        let mut offset = 0u64;
        for (n, (role, bytes, quotes, backslashes, tool)) in REPLAY_SHAPE.into_iter().enumerate() {
            let message = entity(
                IdKind::Message,
                &format!("00000000-0000-4000-8000-0000000000{n:02}"),
            );
            let text = synthetic_text(n, bytes, quotes, backslashes);
            let timestamp = format!("2026-10-17T12:{n:02}:00.000Z");
            batch.entries.push((
                message.clone(),
                serde_json::to_vec(&json!({"role":role,"text":text,"timestamp":timestamp}))
                    .unwrap(),
                text.clone(),
            ));
            let placement = MessagePlacement::new(
                session.clone(),
                document.clone(),
                message.clone(),
                n as u32,
                false,
                Some(EvidenceSpan {
                    start: offset,
                    end: offset + bytes as u64,
                }),
            );
            offset += bytes as u64 + 1;
            if let Some(parent) = messages.last() {
                batch.edges.push(MessageEdge {
                    child_placement_id: placement.id.clone(),
                    parent_message_id: StableId::clone(parent),
                    parent_native_id: None,
                    relation: MessageRelation::Reply,
                });
            }
            if tool {
                batch.activities.push(SourceActivity {
                    message_id: message.clone(),
                    activity: ToolActivity {
                        kind: ToolActivityKind::Command,
                        actor: ToolActivityActor::Main,
                        name: "SyntheticTool".into(),
                        target: Some(format!("synthetic-target-{n}")),
                        status: ToolActivityStatus::Success,
                    },
                });
            }
            placements.push(placement.id.as_str().to_owned());
            batch.placements.push(placement);
            messages.push(message);
        }
        store
            .commit_source(&self.control, &worker, &batch, &observation)
            .unwrap();
        Replay {
            session,
            document,
            messages,
            placements,
        }
    }
}

/// A Robot frame with a fixed request id, so its bytes vary only with the
/// evidence and the elapsed-duration digits.
fn replay_frame(f: &Fixture, args: &[&str]) -> (Value, String) {
    let output = Command::new(BIN)
        .args(["--robot", "--request-id", "replay-request", "--db"])
        .arg(&f.db)
        .args(args)
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 10)),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let wire = String::from_utf8(output.stdout).unwrap();
    for private in [
        "PRIVATE_SOURCE_SENTINEL",
        "PRIVATE_REVISION_ID",
        "private-incarnation",
        "NATIVE_RESUME_SENTINEL",
        "source_path",
        "projection_id",
    ] {
        assert!(!wire.contains(private), "private field escaped: {private}");
    }
    (serde_json::from_str(&wire).unwrap(), wire)
}

#[test]
fn context_returns_complete_31k_replay_session_within_32k_robot_frame() {
    let f = Fixture::new(1, "seed");
    let replay = f.commit_replay();
    let context = |max_bytes: usize| {
        let max_bytes = max_bytes.to_string();
        replay_frame(
            &f,
            &[
                "context",
                replay.session.as_str(),
                "--max-bytes",
                &max_bytes,
                "--max-items",
                "64",
                "--max-messages",
                "64",
            ],
        )
    };
    let assert_complete = |(frame, wire): &(Value, String), limit: usize| {
        assert!(wire.len() <= limit, "{} > {limit}", wire.len());
        assert_eq!(frame["outcome"], "success", "{frame}");
        assert_eq!(frame["warnings"], json!([]), "{frame}");
        assert_eq!(
            frame["data"]["truncation"],
            json!({"truncated":false,"reason":null})
        );
        let ids = frame["data"]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["message_id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let expected = replay
            .messages
            .iter()
            .map(|m| m.as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(ids, expected);
    };
    let complete = context(32 * 1024);
    assert_complete(&complete, 32 * 1024);
    let frame_bytes = complete.1.len();
    // The synthetic session is the 31.8 KB shape that previously kept 6 of 12.
    assert!(
        (30 * 1024..32 * 1024).contains(&frame_bytes),
        "fixture drifted from its 31.8 KB shape: {frame_bytes}"
    );
    let data_bytes = serde_json::to_vec(&complete.0["data"]).unwrap().len();
    eprintln!("replay context: robot frame {frame_bytes} B, data {data_bytes} B");
    // A Robot frame is the measured frame itself, so the selection margin is
    // zero; across processes only the digit count of `duration_ms` varies.
    // `base` is the complete frame without those digits. Each attempt targets
    // the digits last seen and checks the outcome whichever way they moved: no
    // frame exceeds its limit, a successful frame is whole, and a partial one
    // is the Application's prefix with one `response_budget` warning (a halved
    // retry by the final-frame safety net would add a second).
    let digits = |frame: &Value| frame["meta"]["duration_ms"].to_string().len();
    let base = frame_bytes - digits(&complete.0);
    let attempt = |limit: usize| {
        let (frame, wire) = context(limit);
        assert!(wire.len() <= limit, "{} > {limit}", wire.len());
        if frame["outcome"] == "success" {
            assert_complete(&(frame.clone(), wire.clone()), limit);
        } else {
            assert_eq!(frame["warnings"], json!(["response_budget"]), "{frame}");
            assert_eq!(
                frame["data"]["truncation"],
                json!({"truncated":true,"reason":"max_response_bytes"})
            );
            assert_eq!(frame["data"]["messages"].as_array().unwrap().len(), 11);
        }
        (frame, wire.len())
    };
    // A complete frame exactly at its limit is kept whole.
    let mut previous = digits(&complete.0);
    let mut exact = false;
    for _ in 0..5 {
        let limit = base + previous;
        let (frame, bytes) = attempt(limit);
        previous = digits(&frame);
        if frame["outcome"] == "success" && bytes == limit {
            exact = true;
            break;
        }
    }
    assert!(exact, "no call reproduced a frame exactly at its limit");
    // One byte short of the frame keeps the largest fitting prefix. Durations
    // only grow within a call, so a partial frame whose own digits equal the
    // target proves its complete candidate was exactly one byte over.
    let mut short = false;
    for _ in 0..5 {
        let limit = base + previous - 1;
        let (frame, _) = attempt(limit);
        let seen = digits(&frame);
        if frame["outcome"] == "partial" && seen == previous {
            short = true;
            break;
        }
        previous = seen;
    }
    assert!(short, "no call reproduced a frame one byte over its limit");
}

/// Context calls over one MCP session. Call ids are single digits, so the
/// frame lengths of different calls are directly comparable.
fn replay_mcp(f: &Fixture, session: &StableId, calls: &[(usize, usize)]) -> Vec<String> {
    let mut child = Command::new(BIN)
        .arg("--db")
        .arg(&f.db)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}})).unwrap();
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    for (n, (max_bytes, max_messages)) in calls.iter().enumerate() {
        writeln!(input, "{}", json!({"jsonrpc":"2.0","id":n + 2,"method":"tools/call","params":{"name":"get_session_context","arguments":{"session_id":session.as_str(),"max_bytes":max_bytes,"max_messages":max_messages}}})).unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let wire = String::from_utf8(output.stdout).unwrap();
    assert!(!wire.contains("PRIVATE_SOURCE_SENTINEL"));
    let lines = wire
        .split_inclusive('\n')
        .skip(1)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), calls.len(), "{wire}");
    lines
}

fn mcp_payload(line: &str) -> Value {
    let frame: Value = serde_json::from_str(line).unwrap();
    assert_eq!(frame["result"]["isError"], false, "{frame}");
    frame["result"]["structuredContent"].clone()
}

#[test]
fn mcp_context_frame_at_limit_is_complete_and_one_byte_less_keeps_largest_prefix() {
    let f = Fixture::new(1, "seed");
    let replay = f.commit_replay();
    let full = replay_mcp(&f, &replay.session, &[(256 * 1024, 64)]);
    // MCP frame bytes are deterministic: the measurement is the final frame.
    let limit = full[0].len();
    let complete = mcp_payload(&full[0]);
    assert_eq!(complete["data"]["messages"].as_array().unwrap().len(), 12);
    assert_eq!(complete["data"]["truncation"]["truncated"], false);
    let lines = replay_mcp(&f, &replay.session, &[(limit, 64), (limit - 1, 64)]);
    assert_eq!(lines[0].len(), limit, "a frame exactly at its limit fits");
    assert_eq!(mcp_payload(&lines[0]), complete);
    assert!(lines[1].len() < limit);
    let short = mcp_payload(&lines[1]);
    assert_eq!(short["outcome"], "partial");
    // A single warning: the Application measurement is exact, so the
    // final-frame safety net never halves the budget.
    assert_eq!(short["warnings"], json!(["response_budget"]), "{short}");
    assert_eq!(
        short["data"]["truncation"],
        json!({"truncated":true,"reason":"max_response_bytes"})
    );
    let kept = short["data"]["messages"].as_array().unwrap();
    let k = kept.len();
    assert!((1..12).contains(&k), "{k}");
    eprintln!(
        "replay mcp context: complete frame {limit} B; limit {} B keeps {k} of 12 in {} B",
        limit - 1,
        lines[1].len()
    );
    for (message, placement) in kept.iter().zip(&replay.placements) {
        assert_eq!(message["placement_id"], placement.as_str());
    }
    // Largest prefix: the k+1 prefix truncated by count renders 12 bytes
    // shorter than its byte-truncated form (`max_messages` is 6 bytes shorter
    // than `max_response_bytes`, once per payload copy), and still exceeds
    // the limit. The k prefix at exactly its own frame size is kept whole.
    let probe = replay_mcp(
        &f,
        &replay.session,
        &[(256 * 1024, k + 1), (lines[1].len(), 64)],
    );
    let next = mcp_payload(&probe[0]);
    assert_eq!(next["data"]["messages"].as_array().unwrap().len(), k + 1);
    if k + 1 < 12 {
        assert_eq!(next["data"]["truncation"]["reason"], "max_messages");
        assert!(probe[0].len() + 12 > limit - 1);
    }
    assert_eq!(probe[1].len(), lines[1].len());
    assert_eq!(mcp_payload(&probe[1]), short);
}

#[test]
fn mcp_context_at_32k_keeps_the_largest_prefix_of_the_whole_frame_in_one_render() {
    let f = Fixture::new(1, "seed");
    let replay = f.commit_replay();
    // `max_bytes` budgets the whole JSON-RPC frame, which carries the payload
    // twice (once escaped). The session whose single Robot envelope fits in
    // 32 KiB therefore cannot fit whole here.
    let limit = 32 * 1024;
    let lines = replay_mcp(&f, &replay.session, &[(limit, 64)]);
    assert!(lines[0].len() <= limit, "{} > {limit}", lines[0].len());
    let payload = mcp_payload(&lines[0]);
    assert_eq!(payload["outcome"], "partial");
    // One render passes the final-frame gate: a halved retry would add a
    // second `response_budget` warning.
    assert_eq!(payload["warnings"], json!(["response_budget"]), "{payload}");
    assert_eq!(
        payload["data"]["truncation"],
        json!({"truncated":true,"reason":"max_response_bytes"})
    );
    let kept = payload["data"]["messages"].as_array().unwrap();
    let k = kept.len();
    eprintln!(
        "replay mcp context at {limit} B: keeps {k} of 12 in {} B",
        lines[0].len()
    );
    assert_eq!(k, 6, "{payload}");
    for (message, placement) in kept.iter().zip(&replay.placements) {
        assert_eq!(message["placement_id"], placement.as_str());
    }
    // Largest prefix: the k+1 prefix truncated by count is 12 bytes shorter
    // than its byte-truncated form (one 6-byte reason difference per payload
    // copy) and still exceeds the limit.
    let probe = replay_mcp(&f, &replay.session, &[(256 * 1024, k + 1)]);
    let next = mcp_payload(&probe[0]);
    assert_eq!(next["data"]["messages"].as_array().unwrap().len(), k + 1);
    assert_eq!(next["data"]["truncation"]["reason"], "max_messages");
    assert!(probe[0].len() + 12 > limit, "{}", probe[0].len());
}

#[test]
fn context_provenance_rows_are_the_shared_byte_identical_shape() {
    let f = Fixture::new(1, "seed");
    let replay = f.commit_replay();
    let (frame, wire) = replay_frame(
        &f,
        &[
            "context",
            replay.session.as_str(),
            "--max-bytes",
            "65536",
            "--max-items",
            "64",
            "--max-messages",
            "64",
        ],
    );
    let digest = f.observation.revision_digest.as_str();
    let mut expected = vec![
        json!({"entity_id":replay.session.as_str(),"provider_id":"claude-code","session_id":replay.session.as_str(),"message_id":null,"placement_id":null,"document_id":null,"revision_digest":digest,"precision":"unknown","related_revision_digests":[digest]}),
    ];
    for (message, placement) in replay.messages.iter().zip(&replay.placements) {
        expected.push(json!({"entity_id":message.as_str(),"provider_id":"claude-code","session_id":replay.session.as_str(),"message_id":message.as_str(),"placement_id":placement,"document_id":replay.document.as_str(),"revision_digest":digest,"precision":"byte","related_revision_digests":[digest]}));
    }
    let expected = Value::Array(expected);
    assert_eq!(frame["data"]["provenance"], expected);
    // Field order and bytes too: the budget measures this exact row shape.
    assert!(
        wire.contains(&format!("\"provenance\":{expected}")),
        "{wire}"
    );
}
