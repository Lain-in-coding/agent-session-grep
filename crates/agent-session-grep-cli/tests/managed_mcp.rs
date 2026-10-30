//! Real, persistent MCP transports against disposable synthetic Claude history.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
    managed_store::ManagedStore,
};
use agent_session_grep_ports::{PortError, control::*};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{Receiver, channel},
    thread::JoinHandle,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
fn acquire(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => panic!("synthetic lock: {e:?}"),
        }
    }
}
fn line(id: &str, text: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"type":"user","uuid":id,
        "sessionId":"mcp-synthetic-session","timestamp":"2026-01-01T00:00:00Z",
        "message":{"role":"user","content":text}}))
    .unwrap();
    bytes.push(b'\n');
    bytes
}

/// A bare control open or read outside a runtime scope has a 250 ms window,
/// which a loaded host can exhaust although nothing holds a lock. Fixture
/// control work retries only typed contention until one explicit end; every
/// other error still fails the test with its own message.
#[track_caller]
fn bounded_until<T>(
    deadline: Instant,
    what: &str,
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> T {
    loop {
        match operation() {
            Ok(value) => return value,
            Err(
                PortError::WriterBusy(_)
                | PortError::GenerationMismatch(_)
                | PortError::SnapshotChanged(_),
            ) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("synthetic {what}: {error:?}"),
        }
    }
}
#[track_caller]
fn bounded<T>(what: &str, operation: impl FnMut() -> Result<T, PortError>) -> T {
    bounded_until(Instant::now() + Duration::from_secs(3), what, operation)
}

struct Fixture {
    _temp: tempfile::TempDir,
    db: PathBuf,
    transcript: PathBuf,
    selection: ControlId,
    worker: Option<Child>,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let db = temp.path().join("private/catalog.db");
        let history = temp.path().join("history");
        fs::create_dir(&history).unwrap();
        let output = Command::new(BIN)
            .args(["--robot", "--db"])
            .arg(&db)
            .arg("setup")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(10));
        bounded("pause after setup", || {
            let control = SqliteControlStore::open_current_writable(db.parent().unwrap())?;
            control
                .set_desired_updates(control.status()?.policy.control_seq, DesiredUpdates::Paused)
        });
        let output = Command::new(BIN)
            .args(["--robot", "--db"])
            .arg(&db)
            .args(["sources", "add", "--provider", "claude"])
            .arg(&history)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let selection = ControlId::parse(value["data"]["id"].as_str().unwrap()).unwrap();
        let transcript = history.join("synthetic.jsonl");
        fs::write(&transcript, line("m1", "orchid original evidence")).unwrap();
        Self {
            _temp: temp,
            db,
            transcript,
            selection,
            worker: None,
        }
    }
    fn control(&self) -> SqliteControlStore {
        bounded("control open", || {
            SqliteControlStore::open_current_writable(self.db.parent().unwrap())
        })
    }
    fn start(&mut self) {
        let control = self.control();
        bounded("start", || {
            control.set_desired_updates(
                control.status()?.policy.control_seq,
                DesiredUpdates::Running,
            )
        });
        let mut command = Command::new(BIN);
        command
            .arg("__managed-background")
            .arg("--db")
            .arg(&self.db)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        self.worker = Some(command.spawn().unwrap());
    }
    fn pause(&self) {
        let control = self.control();
        bounded("pause", || {
            control
                .set_desired_updates(control.status()?.policy.control_seq, DesiredUpdates::Paused)
        });
    }
    fn revoke(&self) {
        self.pause();
        let control = self.control();
        let owner = acquire(self.db.parent().unwrap(), LockKind::PolicyOwner);
        let deadline = Instant::now() + Duration::from_secs(3);
        let intent = bounded_until(deadline, "revoke", || {
            control.revoke_selection(
                control.status()?.policy.control_seq,
                &self.selection,
                None,
                10,
            )
        })
        .value
        .intent;
        let drain = acquire(self.db.parent().unwrap(), LockKind::PolicyEmission);
        bounded_until(deadline, "settle", || {
            control.settle_revocation(
                control.status()?.policy.control_seq,
                &owner,
                &drain,
                &intent.id,
                11,
            )
        });
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            // A failing test reports whether its worker had already exited;
            // the code is a content-free canonical exit classification.
            if std::thread::panicking()
                && let Ok(Some(status)) = worker.try_wait()
            {
                eprintln!("synthetic worker had exited: {status}");
            }
            let _ = worker.kill();
            let _ = worker.wait();
        }
    }
}

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    frames: Receiver<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
    next: u64,
}
impl Client {
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
                    Ok(_) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut client = Self {
            child,
            input,
            frames,
            reader: Some(reader),
            next: 1,
        };
        let (_, init) = client.request("initialize", json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}));
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client
    }
    fn send(&mut self, value: Value) {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{value}").unwrap();
        input.flush().unwrap();
    }
    fn request(&mut self, method: &str, params: Value) -> (usize, Value) {
        let id = self.next;
        self.next += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let raw = self
            .frames
            .recv_timeout(Duration::from_secs(12))
            .expect("bounded MCP response");
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["id"], id);
        (raw.len(), value)
    }
    fn call(&mut self, name: &str, args: Value) -> (usize, Value) {
        self.request("tools/call", json!({"name":name,"arguments":args}))
    }
    fn wait_hit(&mut self, query: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let (size, result) = self.call("search_sessions", json!({"query":query}));
            assert!(
                size <= 8192,
                "complete duplicate JSON-RPC frame must fit default budget: {size}"
            );
            if result["result"]["structuredContent"]["data"]["hits"]
                .as_array()
                .is_some_and(|h| !h.is_empty())
            {
                return result;
            }
            assert!(
                Instant::now() < deadline,
                "synthetic import was not observed: {result}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn persistent_mcp_observes_append_pause_and_revoke_without_legacy_access() {
    let mut fixture = Fixture::new();
    fixture.start();
    let mut client = Client::connect(&fixture.db);
    let result = client.wait_hit("orchid");
    let payload = &result["result"]["structuredContent"];
    assert_eq!(
        serde_json::from_str::<Value>(result["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap(),
        *payload
    );
    assert!(
        payload["data"]["provenance"]
            .as_array()
            .is_some_and(|p| !p.is_empty())
    );
    // Search now returns verified Session metadata as well as Message hits.
    // Follow the entity kind instead of sending the first ranked Session ID
    // to get_message (which correctly refuses it as invalid params).
    let hits = payload["data"]["hits"].as_array().unwrap();
    let id = hits
        .iter()
        .find_map(|hit| {
            let wire = hit["id"].as_str()?;
            let id = agent_session_grep_domain::StableId::from_wire(wire)?;
            (id.kind() == agent_session_grep_domain::IdKind::Message).then(|| wire.to_owned())
        })
        .expect("search must retain an original Message evidence hit");
    let session_id = hits
        .iter()
        .find_map(|hit| {
            let wire = hit["id"].as_str()?;
            let id = agent_session_grep_domain::StableId::from_wire(wire)?;
            (id.kind() == agent_session_grep_domain::IdKind::Session).then(|| wire.to_owned())
        })
        .expect("same-source first-user Session metadata is searchable");
    OpenOptions::new()
        .append(true)
        .open(&fixture.transcript)
        .unwrap()
        .write_all(&line("m2", "saffron appended evidence"))
        .unwrap();
    client.wait_hit("saffron");
    fixture.pause();
    let (_, paused) = client.call(
        "search_sessions",
        json!({"query":"orchid","latest":true,"max_wait_ms":0}),
    );
    assert_eq!(
        paused["result"]["structuredContent"]["outcome"], "partial",
        "paused latest must return bounded partial state: {paused}"
    );
    assert_eq!(
        paused["result"]["structuredContent"]["data"]["freshness"]["latest_satisfied"],
        false
    );
    assert_eq!(
        paused["result"]["structuredContent"]["data"]["freshness"]["reason"],
        "paused"
    );
    fixture.revoke();
    let (_, revoked) = client.call("search_sessions", json!({"query":"orchid"}));
    assert_eq!(
        revoked["result"]["structuredContent"]["data"]["hits"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let (_, direct) = client.call("get_message", json!({"message_id":id}));
    assert!(!direct.to_string().contains("original evidence"));
    assert_eq!(direct["result"]["isError"], true, "{direct}");
    assert_eq!(
        direct["result"]["structuredContent"]["error"]["canonical_code"],
        "not_found"
    );
    let (_, session) = client.call("get_session_context", json!({"session_id":session_id}));
    assert_eq!(session["result"]["isError"], true, "{session}");
    assert_eq!(
        session["result"]["structuredContent"]["error"]["canonical_code"],
        "not_found"
    );
    assert!(!session.to_string().contains("original evidence"));
}

#[test]
fn idle_mcp_releases_catalog_handles_and_preserves_protocol_validation() {
    let fixture = Fixture::new();
    let mut client = Client::connect(&fixture.db);
    let handle = acquire(fixture.db.parent().unwrap(), LockKind::CatalogHandles);
    drop(handle);
    let (_, catalog) = client.request("tools/list", json!({}));
    let tools = catalog["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 9);
    for tool in tools {
        let hints = &tool["annotations"];
        assert_eq!(
            hints,
            &json!({"readOnlyHint":false,"destructiveHint":false,
            "idempotentHint":false,"openWorldHint":false})
        );
        // Native Codex's auto mode rejects absent hints as destructive/open-world.
        // The actual local, non-destructive coordination effects require neither.
        let requires_approval = hints["destructiveHint"] == true
            || (hints["readOnlyHint"] != true
                && (hints["destructiveHint"] != false || hints["openWorldHint"] != false));
        assert!(
            !requires_approval,
            "{} has conservative unsafe defaults",
            tool["name"]
        );
    }
    let policy_before = fixture.control().status().unwrap().policy;
    let source_before = fs::read(&fixture.transcript).unwrap();
    assert!(
        tools
            .iter()
            .all(|t| t["inputSchema"]["properties"]["latest"]["type"] == "boolean")
    );
    for args in [
        json!({"query":"orchid","latest":"true"}),
        json!({"query":"orchid","max_wait_ms":1}),
        json!({"query":"orchid","providers":["invalid-provider"]}),
        json!({"query":"orchid","unknown":true}),
    ] {
        let (_, value) = client.call("search_sessions", args);
        assert_eq!(value["error"]["code"], -32602, "{value}");
    }
    let (_, value) = client.call("get_status", json!({"latest":true,"max_wait_ms":0}));
    assert_eq!(
        value["result"]["structuredContent"]["data"]["freshness"]["reason"],
        "paused"
    );
    assert_eq!(fixture.control().status().unwrap().policy, policy_before);
    assert_eq!(fs::read(&fixture.transcript).unwrap(), source_before);
    let (_, unknown) = client.call("execute_sql", json!({"query":"select *"}));
    assert_eq!(unknown["error"]["code"], -32602);
}

#[test]
fn maintenance_returns_content_free_business_errors_and_keeps_protocol_alive() {
    let fixture = Fixture::new();
    let mut client = Client::connect(&fixture.db);
    let control = fixture.control();
    let owner = ControlId::parse("synthetic-maintenance").unwrap();
    control
        .set_maintenance(
            control.status().unwrap().policy.control_seq,
            &owner,
            MaintenanceFence {
                state: MaintenanceState::Updating,
                owner: Some(owner.clone()),
                phase: Some(MaintenancePhase::Quiescing),
            },
        )
        .unwrap();
    let (_, ping) = client.request("ping", json!({}));
    assert_eq!(ping["result"], json!({}));
    let (_, result) = client.call("search_sessions", json!({"query":"orchid"}));
    assert_eq!(result["result"]["isError"], true);
    assert!(!result.to_string().contains("original evidence"));
    let (_, ping) = client.request("ping", json!({}));
    assert_eq!(ping["result"], json!({}));
    let input = client.input.as_mut().unwrap();
    input.write_all(&[0xff, b'\n']).unwrap();
    input.flush().unwrap();
    let result: Value =
        serde_json::from_slice(&client.frames.recv_timeout(Duration::from_secs(3)).unwrap())
            .unwrap();
    assert_eq!(result["error"]["code"], -32700);
    control
        .set_maintenance(
            control.status().unwrap().policy.control_seq,
            &owner,
            MaintenanceFence::idle(),
        )
        .unwrap();
    let (_, result) = client.call("get_status", json!({}));
    assert_eq!(result["result"]["isError"], false);
}

#[test]
fn oversized_request_id_cannot_bypass_complete_frame_budget_on_error() {
    let fixture = Fixture::new();
    let mut client = Client::connect(&fixture.db);
    client.send(
        json!({"jsonrpc":"2.0","id":"q".repeat(8192),"method":"tools/call",
        "params":{"name":"search_sessions","arguments":{"query":"synthetic","max_bytes":4096}}}),
    );
    let bytes = client.frames.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(bytes.len() <= 4096);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["id"], Value::Null);
    assert_eq!(value["error"]["code"], -32600);
    let id = "\u{0001}".repeat(128);
    client.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":"search_sessions","arguments":{"query":"synthetic","max_bytes":4096}}}));
    let bytes = client.frames.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(bytes.len() <= 4096);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["id"], id);
}

#[test]
fn managed_mcp_handoff_uses_selected_source_and_complete_frame_budget() {
    let mut fixture = Fixture::new();
    fixture.start();
    let mut client = Client::connect(&fixture.db);
    client.wait_hit("orchid");
    let (size, result) = client.call("generate_handoff", json!({"query":"orchid"}));
    assert!(size <= 8192);
    assert_eq!(result["result"]["isError"], false, "{result}");
    let data = &result["result"]["structuredContent"]["data"];
    assert!(!data["evidence"].as_array().unwrap().is_empty(), "{result}");
    assert!(!data["provenance"].as_array().unwrap().is_empty());
    let (_, restricted) = client.call(
        "generate_handoff",
        json!({"query":"orchid","repo":"example.test/other/repo"}),
    );
    assert!(
        restricted["result"]["structuredContent"]["data"]["evidence"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{restricted}"
    );
    fixture.revoke();
    let (_, result) = client.call("generate_handoff", json!({"query":"orchid"}));
    assert!(!result.to_string().contains("original evidence"));
    assert!(
        result["result"]["structuredContent"]["data"]["evidence"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

fn identity_profile(root: &Path, installation: &str) -> PathBuf {
    let control = SqliteControlStore::create(
        root,
        &ControlId::parse(installation).unwrap(),
        DesiredUpdates::Running,
    )
    .unwrap();
    let db = root.join("catalog.db");
    drop(
        ManagedStore::create(
            &db,
            &control,
            ControlId::parse("synthetic-catalog").unwrap(),
            1,
        )
        .unwrap(),
    );
    let history = root.join("history");
    fs::create_dir(&history).unwrap();
    control
        .add_selection(
            control.status().unwrap().policy.control_seq,
            SelectionRequest {
                region: ScopeRegion {
                    provider: agent_session_grep_ports::SearchProvider::Claude,
                    locator: CanonicalLocator::from_path(&history.canonicalize().unwrap()).unwrap(),
                    kind: RootKind::Root,
                },
                root_identity: Some(RootIdentity::read(&history).unwrap().control_id()),
                now_ms: 2,
            },
        )
        .unwrap();
    let guard = acquire(root, LockKind::Background);
    let worker = control
        .bind_worker(&guard, ControlId::parse("synthetic-worker").unwrap())
        .unwrap();
    control
        .register_worker(
            control.status().unwrap().policy.control_seq,
            &worker,
            std::process::id(),
            3,
        )
        .unwrap();
    // A real, now-released capability leaves an idle registered worker. Latest
    // admits a barrier before discovering that the OS worker lock is available.
    db
}

fn admission_state(root: &Path) -> (i64, i64, i64) {
    let connection = rusqlite::Connection::open(SqliteControlStore::path(root)).unwrap();
    connection.query_row(
        "SELECT control_seq,(SELECT COUNT(*) FROM barriers),(SELECT COUNT(*) FROM cycles) FROM control_meta",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).unwrap()
}

#[test]
fn replaced_physical_root_never_receives_old_connections_latest_admission() {
    for same_installation in [false, true] {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let original = temp.path().join("original");
        let replacement = temp.path().join("replacement");
        let saved = temp.path().join("saved-original");
        let db = identity_profile(&original, "original-installation");
        identity_profile(
            &replacement,
            if same_installation {
                "original-installation"
            } else {
                "replacement-installation"
            },
        );
        let replacement_identity = RootIdentity::read(&replacement).unwrap();
        assert_ne!(RootIdentity::read(&original).unwrap(), replacement_identity);
        let mut client = Client::connect(&db);
        let before = admission_state(&replacement);
        // All paths are distinct children of this disposable test directory.
        // No control connection or guard is retained over either rename.
        fs::rename(&original, &saved).unwrap();
        fs::rename(&replacement, &original).unwrap();
        assert_eq!(RootIdentity::read(&original).unwrap(), replacement_identity);
        let (_, refused) = client.call("get_status", json!({"latest":true,"max_wait_ms":0}));
        assert_eq!(refused["result"]["isError"], true);
        assert_eq!(
            refused["result"]["structuredContent"]["error"]["canonical_code"],
            "schema_incompatible"
        );
        assert_eq!(
            admission_state(&original),
            before,
            "rejected connection wrote replacement control"
        );
        let (_, ping) = client.request("ping", json!({}));
        assert_eq!(ping["result"], json!({}));
        drop(client);
        let mut reconnected = Client::connect(&db);
        let (_, accepted) = reconnected.call("get_status", json!({"latest":true,"max_wait_ms":0}));
        assert_eq!(accepted["result"]["isError"], false);
        assert_eq!(
            accepted["result"]["structuredContent"]["data"]["freshness"]["latest_satisfied"],
            false
        );
        assert_eq!(
            admission_state(&original).1,
            before.1 + 1,
            "new connection did not admit latest"
        );
    }
}

#[test]
fn changed_installation_in_same_root_is_rejected_before_latest_writes() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    let db = identity_profile(&root, "original-installation");
    let identity = RootIdentity::read(&root).unwrap();
    let mut client = Client::connect(&db);
    // Simulate replacing catalog/control identity while retaining the physical
    // directory. Both databases still agree; only the old session differs.
    {
        let control = rusqlite::Connection::open(SqliteControlStore::path(&root)).unwrap();
        control
            .execute(
                "UPDATE control_meta SET installation_id='replacement-installation'",
                [],
            )
            .unwrap();
        let catalog = rusqlite::Connection::open(&db).unwrap();
        catalog
            .execute(
                "UPDATE catalog_meta SET installation_id='replacement-installation'",
                [],
            )
            .unwrap();
    }
    assert_eq!(RootIdentity::read(&root).unwrap(), identity);
    let before = admission_state(&root);
    let (_, refused) = client.call("get_status", json!({"latest":true,"max_wait_ms":0}));
    assert_eq!(refused["result"]["isError"], true);
    assert_eq!(
        refused["result"]["structuredContent"]["error"]["canonical_code"],
        "schema_incompatible"
    );
    assert_eq!(admission_state(&root), before);
    drop(client);
    let mut reconnected = Client::connect(&db);
    let (_, accepted) = reconnected.call("get_status", json!({"latest":true,"max_wait_ms":0}));
    assert_eq!(accepted["result"]["isError"], false);
    assert_eq!(admission_state(&root).1, before.1 + 1);
}

#[test]
fn searched_user_anchor_survives_metadata_break_in_selected_mainline() {
    let mut fixture = Fixture::new();
    let mut transcript = line("m1", "orchid original user decision");
    let assistant = json!({"type":"assistant","uuid":"m2",
        "parentUuid":"unparsed-attachment","sessionId":"mcp-synthetic-session",
        "timestamp":"2026-01-01T00:00:01Z","message":{"role":"assistant",
        "content":"later answer on a metadata-separated branch"}});
    transcript.extend(serde_json::to_vec(&assistant).unwrap());
    transcript.push(b'\n');
    fs::write(&fixture.transcript, &transcript).unwrap();
    fixture.start();
    let mut client = Client::connect(&fixture.db);
    let response = client.wait_hit("orchid");
    let hit = response["result"]["structuredContent"]["data"]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"].as_str().unwrap().starts_with("msg_"))
        .unwrap();
    let message = hit["id"].clone();
    let session = hit["session_id"].clone();
    for around in [0, 2] {
        let (_, response) = client.call(
            "get_message",
            json!({
            "message_id":message,"session_id":session,"around":around,"max_bytes":12000}),
        );
        assert_ne!(response["result"]["isError"], true, "{response}");
        let payload = &response["result"]["structuredContent"];
        assert_eq!(payload["data"]["messages"].as_array().unwrap().len(), 1);
        assert!(
            payload["data"]["messages"][0]["payload"]["text"]
                .as_str()
                .unwrap()
                .contains("original user decision")
        );
        assert_eq!(payload["data"]["provenance"][0]["message_id"], message);
        let unavailable = payload["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "context_unavailable");
        assert_eq!(unavailable, around != 0);
        assert!(!payload.to_string().contains("later answer on"));
    }
    assert_eq!(fs::read(&fixture.transcript).unwrap(), transcript);
}
