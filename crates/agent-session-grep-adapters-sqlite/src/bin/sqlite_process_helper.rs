//! Non-user-facing subprocess helper for SQLite production-path integration evidence.

use agent_session_grep_adapters_sqlite::SqliteStore;
use agent_session_grep_domain::{IdKind, Stability, StableId};
use agent_session_grep_ports::{CatalogStore, PortError};
use std::env;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).ok_or("missing command")?;
    let db = args.get(1).ok_or("missing database path")?;

    match command {
        "hold" => {
            let _store = SqliteStore::open_for_write(db).map_err(format_port_error)?;
            println!("READY");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        "try-open" => match SqliteStore::open_for_write(db) {
            Ok(_) => {
                println!("ACQUIRED");
                Ok(())
            }
            Err(PortError::WriterBusy(message)) => {
                println!("BUSY:{message}");
                Ok(())
            }
            Err(error) => Err(format_port_error(error)),
        },
        "seed" => {
            let store = SqliteStore::open_for_write(db).map_err(format_port_error)?;
            let entry = seed_entry();
            store
                .commit_batch(std::slice::from_ref(&entry))
                .map_err(format_port_error)?;
            println!("SEEDED:{}", entry.0.as_str());
            Ok(())
        }
        "begin-intent" => {
            let store = SqliteStore::open_for_write(db).map_err(format_port_error)?;
            let entry = interrupted_entry();
            let pending = store
                .begin_index_batch(std::slice::from_ref(&entry), &[])
                .map_err(format_port_error)?;
            println!("INTENT:{}:{}", pending.operation_id, entry.0.as_str());
            Ok(())
        }
        "compact-stage" => {
            // 中断边界注入：preview+stage 已 durable 落盘后阻塞，父进程直接 kill。
            // 子进程不再做任何写操作，复现"apply 前进程消失"的崩溃形状。
            let store = SqliteStore::open_for_write(db).map_err(format_port_error)?;
            let preview = store
                .preview_journal_compaction()
                .map_err(format_port_error)?;
            let stage = store
                .stage_journal_compaction(&preview)
                .map_err(format_port_error)?;
            println!("STAGED:{}:{}", stage.compaction_id, stage.affected_batches);
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        "recover" => {
            let store = SqliteStore::open_for_write(db).map_err(format_port_error)?;
            println!(
                "RECOVERED:generation={}:count={}:building={}",
                store.active_generation().map_err(format_port_error)?,
                store.count().map_err(format_port_error)?,
                store.interrupted_batch_count().map_err(format_port_error)?
            );
            Ok(())
        }
        "stale-commit" => {
            let store = SqliteStore::open_for_write(db).map_err(format_port_error)?;
            let entry = stale_entry();
            let pending = store
                .begin_index_batch(std::slice::from_ref(&entry), &[])
                .map_err(format_port_error)?;

            fault_inject_generation_advance(db)?;

            match store.commit_index_batch(&pending, std::slice::from_ref(&entry), &[]) {
                Err(PortError::Backend(message)) if message.contains("generation CAS failed") => {
                    println!(
                        "STALE_REJECTED:generation={}:count={}",
                        store.active_generation().map_err(format_port_error)?,
                        store.count().map_err(format_port_error)?
                    );
                    Ok(())
                }
                Err(error) => Err(format!("unexpected stale commit error: {error}")),
                Ok(()) => Err("stale commit unexpectedly succeeded".into()),
            }
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn format_port_error(error: PortError) -> String {
    error.to_string()
}

fn entry(fact: &[u8], payload: &[u8], text: &str) -> (StableId, Vec<u8>, String) {
    (
        StableId::derive(IdKind::Message, Stability::Reconstructed, &[fact]),
        payload.to_vec(),
        text.to_string(),
    )
}

fn seed_entry() -> (StableId, Vec<u8>, String) {
    entry(b"process-seed", b"user\tseed payload", "seed payload")
}

fn interrupted_entry() -> (StableId, Vec<u8>, String) {
    entry(
        b"process-interrupted",
        b"user\tinterrupted payload",
        "interrupted payload",
    )
}

fn stale_entry() -> (StableId, Vec<u8>, String) {
    entry(b"process-stale", b"user\tstale payload", "stale payload")
}

fn fault_inject_generation_advance(db: &str) -> Result<(), String> {
    // Test-only fault injection: emulate an already-activated competing generation while
    // retaining the production writer store so commit_index_batch exercises its CAS guard.
    let conn = rusqlite::Connection::open(db).map_err(|e| e.to_string())?;
    conn.execute(
        "UPDATE store_metadata SET active_generation = active_generation + 1 WHERE singleton = 1",
        [],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
