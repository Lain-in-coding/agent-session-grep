use agent_session_grep_adapters_sqlite::SqliteStore;
use agent_session_grep_ports::CatalogStore;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sqlite_process_helper")
}

fn db_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn run(command: &str, db: &Path) -> Output {
    Command::new(helper())
        .args([command, &db_arg(db)])
        .output()
        .unwrap()
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn start_holder(db: &Path) -> Child {
    let mut child = Command::new(helper())
        .args(["hold", &db_arg(db)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "READY");
    child
}

#[test]
fn production_open_for_write_allows_exactly_one_process() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let mut holder = start_holder(&db);

    let contender = run("try-open", &db);
    assert!(contender.status.success(), "{}", output_text(&contender));
    let stdout = String::from_utf8_lossy(&contender.stdout);
    let data_root = dir.path().to_string_lossy();
    assert!(stdout.starts_with("BUSY:"), "{}", output_text(&contender));
    assert!(
        !stdout.contains(data_root.as_ref()),
        "writer-busy output disclosed the data-root path: {stdout}"
    );

    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success());
    let next = run("try-open", &db);
    assert!(next.status.success(), "{}", output_text(&next));
    assert_eq!(String::from_utf8_lossy(&next.stdout).trim(), "ACQUIRED");
}

#[test]
fn killed_holder_releases_production_writer_lease_without_deleting_lock_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let mut holder = start_holder(&db);
    let lock_path = dir.path().join("writer.lock");
    assert!(lock_path.exists());

    holder.kill().unwrap();
    holder.wait().unwrap();
    assert!(lock_path.exists());

    let next = run("try-open", &db);
    assert!(next.status.success(), "{}", output_text(&next));
    assert_eq!(String::from_utf8_lossy(&next.stdout).trim(), "ACQUIRED");
}

#[test]
fn production_open_recovers_durable_intent_without_changing_catalog_or_generation() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");

    let seed = run("seed", &db);
    assert!(seed.status.success(), "{}", output_text(&seed));
    let intent = run("begin-intent", &db);
    assert!(intent.status.success(), "{}", output_text(&intent));
    let stdout = String::from_utf8_lossy(&intent.stdout);
    let mut parts = stdout.trim().split(':');
    assert_eq!(parts.next(), Some("INTENT"));
    let operation_id = parts.next().unwrap().to_string();
    let interrupted_id = parts.next().unwrap().to_string();

    {
        let store = SqliteStore::open(&db_arg(&db)).unwrap();
        assert_eq!(store.active_generation().unwrap(), 1);
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.interrupted_batch_count().unwrap(), 1);
        assert!(
            store
                .list(10)
                .unwrap()
                .iter()
                .all(|entry| entry.id.as_str() != interrupted_id)
        );
    }

    let recovered = run("recover", &db);
    assert!(recovered.status.success(), "{}", output_text(&recovered));
    assert_eq!(
        String::from_utf8_lossy(&recovered.stdout).trim(),
        "RECOVERED:generation=1:count=1:building=0"
    );

    let store = SqliteStore::open_for_write(&db_arg(&db)).unwrap();
    assert_eq!(store.active_generation().unwrap(), 1);
    assert_eq!(store.count().unwrap(), 1);
    assert_eq!(store.interrupted_batch_count().unwrap(), 0);
    let batch = store.index_batch(&operation_id).unwrap().unwrap();
    assert_eq!(batch.state, "aborted");
    assert_eq!(
        batch.error_code.as_deref(),
        Some("interrupted_before_activation")
    );
}

#[test]
fn stale_generation_intent_fails_closed_on_production_store() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");

    let stale = run("stale-commit", &db);
    assert!(stale.status.success(), "{}", output_text(&stale));
    assert_eq!(
        String::from_utf8_lossy(&stale.stdout).trim(),
        "STALE_REJECTED:generation=1:count=0"
    );

    let store = SqliteStore::open(&db_arg(&db)).unwrap();
    assert_eq!(store.active_generation().unwrap(), 1);
    assert_eq!(store.count().unwrap(), 0);
}
