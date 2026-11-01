//! Real worker/latest over synthetic Claude metadata; no native host or owner history.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore, managed_locks::RootIdentity, managed_store::ManagedStore,
};
use agent_session_grep_ports::{
    SearchProvider,
    control::{
        CanonicalLocator, ControlId, ControlStore, DesiredUpdates, RootKind, ScopeRegion,
        SelectionRequest,
    },
};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");

struct Worker {
    child: Child,
    temp: tempfile::TempDir,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.temp.disable_cleanup(true);
        let stopped = self.child.try_wait().and_then(|status| {
            if status.is_none() {
                self.child.kill()?;
            }
            self.child.wait()
        });
        if stopped.is_ok() {
            self.temp.disable_cleanup(false);
        } else if std::thread::panicking() {
            eprintln!("synthetic metadata worker cleanup failed; root retained");
        } else {
            panic!("synthetic metadata worker cleanup failed; root retained");
        }
    }
}

fn command(temp: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .current_dir(temp)
        .env("HOME", temp)
        .env("USERPROFILE", temp)
        .env("APPDATA", temp)
        .env("LOCALAPPDATA", temp)
        .env("XDG_CONFIG_HOME", temp)
        .env("XDG_DATA_HOME", temp)
        .stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
}

fn read(temp: &Path, db: &Path, args: &[&str]) -> Value {
    let output = command(temp)
        .args(["--robot", "--db"])
        .arg(db)
        .args(args)
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 10)),
        "synthetic metadata read failed: exit={:?}",
        output.status.code()
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn diagnose_latest_failure(db: &Path) {
    // This is a later diagnostic snapshot, never proof for the failed response.
    // Read only content-free state from this fixture; do not retry the request.
    let end = Instant::now() + Duration::from_millis(250);
    let result = (|| -> rusqlite::Result<()> {
        let connection = rusqlite::Connection::open_with_flags(
            SqliteControlStore::path(db.parent().unwrap()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::ZERO)?;
        connection.progress_handler(1000, Some(move || Instant::now() >= end))?;
        connection.execute_batch("BEGIN")?;
        let worker = connection.query_row(
            "SELECT effective_state,last_error FROM worker_state WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )?;
        eprintln!("synthetic metadata worker state/error={worker:?}");
        let mut statement = connection.prepare(
            "SELECT b.state,b.error_code,b.required_cycle_seq,c.state,\
             s.discovery_complete,s.discovered_count,s.observed_count,s.committed_count,s.error_code \
             FROM barriers b LEFT JOIN cycles c ON c.cycle_seq=b.required_cycle_seq \
             LEFT JOIN cycle_selections s ON s.cycle_seq=c.cycle_seq \
             ORDER BY b.admission_control_seq DESC LIMIT 4",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut count = 0;
        for row in rows {
            eprintln!("synthetic metadata barrier/cycle/counts/error={:?}", row?);
            count += 1;
        }
        eprintln!("synthetic metadata barrier rows={count}");
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("synthetic metadata latest diagnostics unavailable: {error:?}");
    }
}

#[test]
fn claude_runtime_metadata_publishes_original_and_satisfies_latest() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let history = temp.path().join("history");
    fs::create_dir(&history).unwrap();
    let path = history.join("synthetic.jsonl");
    let original = "metadataoriginal synthetic assistant decision";
    let rows = [
        json!({"type":"atis-latch","atis":"synthetic first latch","sessionId":"synthetic-session"}),
        json!({"type":"user","uuid":"synthetic-user","sessionId":"synthetic-session",
            "timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":"synthetic request"}}),
        json!({"type":"assistant","uuid":"synthetic-assistant","parentUuid":"synthetic-user",
            "sessionId":"synthetic-session","timestamp":"2026-01-01T00:00:01Z",
            "message":{"role":"assistant","content":original,"usage":{"input_tokens":7,"output_tokens":3}}}),
        json!({"type":"atis-latch","atis":"synthetic final latch","sessionId":"synthetic-session"}),
        json!({"type":"cost-state","sessionId":"synthetic-session","totalCostUSD":0.25,
            "totalAPIDuration":23,"totalAPIDurationWithoutRetries":19,"totalToolDuration":4,
            "totalLinesAdded":3,"totalLinesRemoved":1,"totalDuration":29,
            "startTime":1_700_000_000_000_u64,"modelUsage":{"synthetic-model":{
                "inputTokens":700,"outputTokens":300,"cacheReadInputTokens":200,
                "cacheCreationInputTokens":100,"webSearchRequests":0,"costUSD":0.25,
                "thinkingTokens":100}},"hasUnknownModelCost":false}),
    ];
    let bytes = rows
        .iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>()
        .into_bytes();
    fs::write(&path, &bytes).unwrap();
    let root = temp.path().join("private");
    let db = root.join("catalog.db");
    let control = SqliteControlStore::create(
        &root,
        &ControlId::parse("synthetic-metadata-installation").unwrap(),
        DesiredUpdates::Running,
    )
    .unwrap();
    let selected = history.canonicalize().unwrap();
    control
        .add_selection(
            control.status().unwrap().policy.control_seq,
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Claude,
                    locator: CanonicalLocator::from_path(&selected).unwrap(),
                    kind: RootKind::Root,
                },
                root_identity: Some(RootIdentity::read(&selected).unwrap().control_id()),
                now_ms: 1,
            },
        )
        .unwrap();
    drop(
        ManagedStore::create(
            &db,
            &control,
            ControlId::parse("synthetic-metadata-catalog").unwrap(),
            1,
        )
        .unwrap(),
    );
    drop(control);
    let child = command(temp.path())
        .args(["__managed-background", "--db"])
        .arg(&db)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut worker = Worker { child, temp };
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let status = read(worker.temp.path(), &db, &["background", "status"]);
        if status["data"]["running"] == true {
            break;
        }
        assert!(worker.child.try_wait().unwrap().is_none());
        assert!(
            Instant::now() < end,
            "synthetic metadata worker did not start"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    // One `--latest` request waits out admission contention and a live worker
    // Busy or Deferred advisory within its own wait, so either reason here is
    // a defect. SourceChanged still ends its barrier; only that reason
    // re-admits a fresh request inside one original end. Any other reason
    // fails at once.
    let latest_end = Instant::now() + Duration::from_secs(10);
    let mut attempts = 0_u32;
    let mut transient: Vec<String> = Vec::new();
    let mut last = Value::Null;
    let search = loop {
        let remaining_ms = latest_end
            .saturating_duration_since(Instant::now())
            .as_millis();
        if remaining_ms == 0 {
            diagnose_latest_failure(&db);
            panic!(
                "synthetic metadata latest expired: attempts={attempts}, \
                 transient={transient:?}, last freshness={last}"
            );
        }
        attempts += 1;
        let wait = remaining_ms.to_string();
        let search = read(
            worker.temp.path(),
            &db,
            &[
                "search",
                "metadataoriginal",
                "--latest",
                "--max-wait-ms",
                wait.as_str(),
            ],
        );
        let freshness = &search["data"]["freshness"];
        if freshness["latest_satisfied"] == true {
            break search;
        }
        let reason = freshness["reason"].as_str().unwrap_or("missing").to_owned();
        if reason != "source_changed" {
            diagnose_latest_failure(&db);
            panic!(
                "synthetic metadata latest failed: attempts={attempts}, \
                 transient={transient:?}, reason={reason}, freshness={freshness}"
            );
        }
        last.clone_from(freshness);
        transient.push(reason);
        // Latest projects the stored heartbeat state; check the real process
        // before re-admitting so a dead worker cannot look transiently busy.
        if worker.child.try_wait().unwrap().is_some() {
            diagnose_latest_failure(&db);
            panic!(
                "synthetic metadata worker exited during latest: attempts={attempts}, \
                 transient={transient:?}, last freshness={last}"
            );
        }
        // Each admission takes the control write lock; stay well below the
        // worker cadence without adding writer pressure.
        let remaining = latest_end.saturating_duration_since(Instant::now());
        std::thread::sleep(Duration::from_millis(100).min(remaining));
    };
    let freshness = &search["data"]["freshness"];
    assert_eq!(
        freshness["latest_satisfied"], true,
        "synthetic metadata latest failed: freshness={freshness}"
    );
    assert_eq!(freshness["coverage"], "complete");
    assert_eq!(freshness["pending_sources"], 0);
    assert_eq!(freshness["contributing_sources"], 1);
    assert_eq!(search["data"]["hits"].as_array().unwrap().len(), 1);
    let proof = search["data"]["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .find(|proof| proof["message_id"].is_string())
        .unwrap();
    assert_eq!(proof["provider_id"], "claude-code");
    assert_eq!(proof["precision"], "byte");
    assert!(
        proof["document_id"]
            .as_str()
            .unwrap()
            .starts_with("doc_v1_")
    );
    assert_eq!(
        proof["revision_digest"],
        blake3::hash(&bytes).to_hex().to_string()
    );
    let message = proof["message_id"].as_str().unwrap();
    let session = proof["session_id"].as_str().unwrap();
    let show = read(worker.temp.path(), &db, &["show", message]);
    assert_eq!(show["data"]["entity"]["text"], original);
    let context = read(
        worker.temp.path(),
        &db,
        &[
            "context",
            session,
            "--policy",
            "full",
            "--max-bytes",
            "32768",
        ],
    );
    let messages = context["data"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().any(|message| {
        message["message_id"] == proof["message_id"]
            && message["payload"]["role"] == "assistant"
            && message["payload"]["text"] == original
    }));
    let original_proof = context["data"]["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .find(|proof| proof["message_id"] == message)
        .unwrap();
    assert_eq!(original_proof["session_id"], session);
    assert_eq!(original_proof["document_id"], proof["document_id"]);
    assert_eq!(original_proof["revision_digest"], proof["revision_digest"]);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}
