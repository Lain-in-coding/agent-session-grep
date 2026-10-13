//! Journal maintenance command boundary and detached worker composition.
use crate::CliError;
use crate::protocol::{self, CanonicalCode, Outcome, OutputMode, ProtocolError};

pub(crate) const HELP: &str = "journal — durable online journal maintenance
USAGE:
    asg [--db <catalog>] journal preview
    asg [--db <catalog>] journal submit --plan <token> [--max-write-seconds <n>]
    asg [--db <catalog>] journal status [job-id]
    asg [--db <catalog>] journal cancel <job-id>
    asg [--db <catalog>] journal retry <job-id> [--max-write-seconds <n>]
    asg [--db <catalog>] journal worker start|stop

Preview is read-only. Submit confirms only the previewed terminal batches.
The default writer-lock soft budget is 30 seconds per acquisition; only an
explicit positive override changes it. Noninterruptible I/O can exceed it.
Jobs survive CLI exit. Only submit/retry/start and successful existing writes
may wake an existing unpaused queue. Reads and help never wake a worker.
Worker stop persists a pause; only worker start clears it. Cancel cannot undo
committed compaction. Once cleanup is claimed, cancellation_closed=true means
cancellation is too late; cleanup must finish or be retried. Failed/cancelled
jobs retain their verified backup.
Global --db, --robot, --output and --request-id flags must precede journal.
";

#[derive(Debug, PartialEq, Eq)]
enum Request {
    Preview,
    Submit { token: String, budget: Option<u64> },
    Status(Option<String>),
    Cancel(String),
    Retry { id: String, budget: Option<u64> },
    Start,
    Stop,
    Run,
}

fn parse(rest: &[String]) -> Result<Request, CliError> {
    let mut args = rest.get(1..).unwrap_or_default().to_vec();
    let command = args.first().map(String::as_str).unwrap_or("");
    match command {
        "preview" if args.len() == 1 => Ok(Request::Preview),
        "status" if args.len() <= 2 => {
            if let Some(id) = args.get(1) {
                validate_opaque(id)?;
            }
            Ok(Request::Status(args.get(1).cloned()))
        }
        "cancel" if args.len() == 2 => {
            validate_opaque(&args[1])?;
            Ok(Request::Cancel(args[1].clone()))
        }
        "submit" | "retry" => {
            let submit = command == "submit";
            let budget = take_value(&mut args, "--max-write-seconds")?
                .map(|value| {
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(CliError::usage(
                            "--max-write-seconds requires a positive integer",
                        ));
                    }
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|value| {
                            *value > 0
                                && std::time::Instant::now()
                                    .checked_add(std::time::Duration::from_secs(*value))
                                    .is_some()
                        })
                        .ok_or_else(|| {
                            CliError::usage("--max-write-seconds requires a positive integer")
                        })
                })
                .transpose()?;
            if submit {
                let token = take_value(&mut args, "--plan")?
                    .ok_or_else(|| CliError::usage("journal submit requires --plan <token>"))?;
                validate_opaque(&token)?;
                if args.len() != 1 {
                    return Err(usage());
                }
                Ok(Request::Submit { token, budget })
            } else {
                if args.len() != 2 {
                    return Err(usage());
                }
                validate_opaque(&args[1])?;
                Ok(Request::Retry {
                    id: args[1].clone(),
                    budget,
                })
            }
        }
        "worker" if args.len() == 2 => match args[1].as_str() {
            "start" => Ok(Request::Start),
            "stop" => Ok(Request::Stop),
            "__run" => Ok(Request::Run),
            _ => Err(usage()),
        },
        _ => Err(usage()),
    }
}

fn usage() -> CliError {
    CliError::usage(
        "journal expects preview|submit --plan <token>|status [job-id]|cancel <job-id>|retry <job-id>|worker start|stop",
    )
}

fn validate_opaque(value: &str) -> Result<(), CliError> {
    if !(1..=256).contains(&value.len())
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(CliError::usage(
            "invalid maintenance identifier or plan token",
        ));
    }
    Ok(())
}

// Unlike generic query flag extraction, maintenance errors never echo token/path input.
fn take_value(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, CliError> {
    let mut positions = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.as_str() == flag)
        .map(|(i, _)| i);
    let Some(position) = positions.next() else {
        return Ok(None);
    };
    if positions.next().is_some() {
        return Err(CliError::usage("duplicate maintenance flag"));
    }
    if args
        .get(position + 1)
        .is_none_or(|value| value.starts_with('-'))
    {
        return Err(CliError::usage("maintenance flag requires a value"));
    }
    args.remove(position);
    Ok(Some(args.remove(position)))
}

use agent_session_grep_adapters_sqlite::{
    maintenance::{
        SqliteMaintenanceCatalog, maintenance_root, maintenance_target_path, worker_temp_directory,
    },
    maintenance_queue::{QueueLock, SqliteMaintenanceQueue},
};
use agent_session_grep_application::maintenance::MaintenanceService;
use agent_session_grep_ports::{
    PortError, PortResult, RetrievalMode,
    maintenance::{MaintenanceCatalog, MaintenanceControl, MaintenanceJob, MaintenanceQueue},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const WORKER_IDLE: Duration = Duration::from_secs(30);
const CONTROL_POLL: Duration = Duration::from_millis(50);
const WAKE_WARNING: &str =
    "maintenance task remains saved; worker could not be started; use journal worker start";

fn private_error(error: PortError) -> CliError {
    ProtocolError::from_private_port_error(error).into()
}
fn clock_ms() -> u64 {
    agent_session_grep_application::system_now_ms().max(0) as u64
}

pub(crate) fn run(
    db: &str,
    rest: &[String],
    mode: OutputMode,
    request_id: Option<&str>,
) -> Result<Outcome, CliError> {
    // No path resolution, queue creation, or catalog open before full validation.
    let request = parse(rest)?;
    let started = Instant::now();
    let catalog = SqliteMaintenanceCatalog::new();
    let root = maintenance_root(Path::new(db)).map_err(private_error)?;
    let target = maintenance_target_path(Path::new(db)).map_err(private_error)?;
    let target = target
        .to_str()
        .ok_or_else(|| CliError::usage("maintenance target is not UTF-8"))?;
    if request == Request::Run {
        worker(&root, &catalog).map_err(private_error)?;
        return Ok(Outcome::Success);
    }
    let mut warnings = Vec::new();
    let (command, data) = match request {
        Request::Preview => {
            let preview = catalog.preview(target).map_err(private_error)?;
            // Deliberately do not serialize the private target or selection manifest.
            (
                "journal.preview",
                json!({
                    "plan": preview.token,
                    "affected_batches": preview.selection.batches.len(),
                    "detail_bytes_before": preview.selection.detail_bytes_before,
                    "estimated_detail_bytes_after": preview.selection.estimated_detail_bytes_after,
                    "estimated_saved_bytes": preview.selection.estimated_saved_bytes,
                    "footprint": preview.footprint,
                }),
            )
        }
        Request::Status(id) => {
            let queue = SqliteMaintenanceQueue::open_existing(&root).map_err(private_error)?;
            let jobs = match &queue {
                Some(queue) => match id {
                    Some(id) => {
                        let job = queue.get(&id).map_err(private_error)?;
                        if job.target.canonical_path != target {
                            return Err(private_error(PortError::NotFound(
                                "maintenance job not found for target".into(),
                            )));
                        }
                        vec![job.summary()]
                    }
                    None => queue
                        .list(Some(target))
                        .map_err(private_error)?
                        .iter()
                        .map(MaintenanceJob::summary)
                        .collect(),
                },
                None if id.is_some() => {
                    return Err(private_error(PortError::NotFound(
                        "maintenance job not found".into(),
                    )));
                }
                None => Vec::new(),
            };
            (
                "journal.status",
                json!({"jobs": jobs, "worker": worker_status(&root, queue.as_ref()).map_err(private_error)?}),
            )
        }
        Request::Submit { token, budget } => {
            let queue = SqliteMaintenanceQueue::open(&root).map_err(private_error)?;
            let _lifecycle = QueueLock::lifecycle(&root).map_err(private_error)?;
            let service = MaintenanceService::new(&queue, &catalog, clock_ms);
            let job = service
                .submit(target, &token, budget)
                .map_err(private_error)?;
            let wake = wake_locked(&root, target, &queue);
            if wake.is_err() {
                warnings.push(WAKE_WARNING.to_owned());
            }
            (
                "journal.submit",
                json!({"job": job.summary(), "worker": wake.unwrap_or_else(|_| json!({"state": "start_failed"}))}),
            )
        }
        Request::Cancel(id) => {
            let queue = existing_queue(&root)?;
            let job = queue.request_cancel(&id).map_err(private_error)?;
            (
                "journal.cancel",
                json!({"job": job.summary(), "worker": worker_status(&root, Some(&queue)).map_err(private_error)?}),
            )
        }
        Request::Retry { id, budget } => {
            let queue = existing_queue(&root)?;
            let _lifecycle = QueueLock::lifecycle(&root).map_err(private_error)?;
            let service = MaintenanceService::new(&queue, &catalog, clock_ms);
            let job = service.retry(&id, budget).map_err(private_error)?;
            let wake = wake_locked(&root, target, &queue);
            if wake.is_err() {
                warnings.push(WAKE_WARNING.to_owned());
            }
            (
                "journal.retry",
                json!({"job": job.summary(), "worker": wake.unwrap_or_else(|_| json!({"state": "start_failed"}))}),
            )
        }
        Request::Start => {
            let queue =
                SqliteMaintenanceQueue::open_existing_writable(&root).map_err(private_error)?;
            let worker = if let Some(queue) = &queue {
                let _lifecycle = QueueLock::lifecycle(&root).map_err(private_error)?;
                queue.set_paused(false).map_err(private_error)?;
                let wake = wake_locked(&root, target, queue);
                if wake.is_err() {
                    warnings.push(WAKE_WARNING.to_owned());
                }
                wake.unwrap_or_else(|_| json!({"state": "start_failed"}))
            } else {
                worker_status(&root, None).map_err(private_error)?
            };
            ("journal.worker.start", json!({"worker": worker}))
        }
        Request::Stop => {
            // Explicit stop persists a pause even before the first submission.
            let queue = SqliteMaintenanceQueue::open(&root).map_err(private_error)?;
            let _lifecycle = QueueLock::lifecycle(&root).map_err(private_error)?;
            queue.set_paused(true).map_err(private_error)?;
            (
                "journal.worker.stop",
                json!({"worker": worker_status(&root, Some(&queue)).map_err(private_error)?}),
            )
        }
        Request::Run => unreachable!(),
    };
    crate::emit_result(
        command,
        mode,
        Outcome::Success,
        data,
        started.elapsed().as_millis() as u64,
        &protocol::Page::default(),
        &warnings,
        request_id,
        RetrievalMode::Lexical,
    );
    Ok(Outcome::Success)
}

fn existing_queue(root: &Path) -> Result<SqliteMaintenanceQueue, CliError> {
    SqliteMaintenanceQueue::open_existing_writable(root)
        .map_err(private_error)?
        .ok_or_else(|| {
            CliError(ProtocolError::new(
                CanonicalCode::NotFound,
                "maintenance queue not found",
            ))
        })
}

fn worker_status(root: &Path, queue: Option<&SqliteMaintenanceQueue>) -> PortResult<Value> {
    let Some(queue) = queue else {
        return Ok(
            json!({"queue_exists": false, "paused": false, "running": false, "state": "absent"}),
        );
    };
    let paused = queue.control(None)?.paused;
    let running = QueueLock::worker_running(root)?;
    Ok(
        json!({"queue_exists": true, "paused": paused, "running": running,
        "state": if paused { "paused" } else if running { "running" } else { "stopped" }}),
    )
}

// The caller holds lifecycle from durable enqueue/control update through spawn.
fn wake_locked(root: &Path, target: &str, queue: &SqliteMaintenanceQueue) -> PortResult<Value> {
    let state = worker_status(root, Some(queue))?;
    if queue.control(None)?.paused
        || QueueLock::worker_running(root)?
        || !queue.list(None)?.iter().any(|job| job.state.is_runnable())
    {
        return Ok(state);
    }
    spawn_worker(root, target)
        .map_err(|_| PortError::Backend("maintenance worker spawn failed".into()))?;
    Ok(json!({"queue_exists": true, "paused": false, "running": false, "state": "starting"}))
}

/// Best effort only AFTER a successful ordinary writer has dropped its store.
/// Does not create even a lock directory when no queue exists.
pub(crate) fn wake_after_write(db: &str) -> Option<String> {
    let result = (|| -> PortResult<()> {
        let root = maintenance_root(Path::new(db))?;
        let Some(queue) = SqliteMaintenanceQueue::open_existing_writable(&root)? else {
            return Ok(());
        };
        let _lifecycle = QueueLock::lifecycle(&root)?;
        let target = maintenance_target_path(Path::new(db))?;
        let target = target
            .to_str()
            .ok_or_else(|| PortError::Backend("maintenance target unavailable".into()))?;
        wake_locked(&root, target, &queue)?;
        Ok(())
    })();
    result.err().map(|_| WAKE_WARNING.to_owned())
}

fn spawn_worker(root: &Path, target: &str) -> std::io::Result<()> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let temp = worker_temp_directory(root)
        .map_err(|_| std::io::Error::other("private worker temp unavailable"))?;
    let mut command = Command::new(executable);
    command
        .args(["--db", target, "journal", "worker", "__run"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in ["TMP", "TEMP", "TMPDIR", "SQLITE_TMPDIR"] {
        command.env(name, &temp);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no console, no inherited
        // Ctrl-C process group. CREATE_NO_WINDOW is redundant with DETACHED_PROCESS.
        command.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe; no allocation/locks in pre_exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    let mut parent_stdio = ParentStdioInheritance::suspend()?;
    let spawned = command.spawn();
    #[cfg(windows)]
    let restored = parent_stdio.restore();
    let mut child = spawned?;
    #[cfg(windows)]
    restored?;
    // A reaper prevents zombies if an embedding caller stays alive. Process exit
    // does not wait for this thread and dropping Child never terminates the worker.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Rust's MSRV-compatible Windows Command passes bInheritHandles=TRUE even
/// with all three child streams set to NUL. Do not leak the ORIGINAL parent
/// pipe handles: a caller waiting for EOF would otherwise wait for the daemon.
/// This composition root spawns only after ordinary writer/provider work ended.
#[cfg(windows)]
struct ParentStdioInheritance(Vec<(windows_sys::Win32::Foundation::HANDLE, u32)>);
#[cfg(windows)]
impl ParentStdioInheritance {
    fn suspend() -> std::io::Result<Self> {
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        // SAFETY: GetStdHandle borrows the process's existing standard handles.
        let handles = unsafe {
            [
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetStdHandle(STD_ERROR_HANDLE),
            ]
        };
        Self::suspend_handles(&handles)
    }

    fn suspend_handles(
        handles: &[windows_sys::Win32::Foundation::HANDLE],
    ) -> std::io::Result<Self> {
        use windows_sys::Win32::Foundation::{
            GetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
        };
        let mut guard = Self(Vec::new());
        for &handle in handles {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                continue;
            }
            // SAFETY: borrowed handles remain open; only their inheritance bit
            // changes, and restore/Drop restores the exact original bit.
            unsafe {
                let mut flags = 0;
                if GetHandleInformation(handle, &mut flags) == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if flags & HANDLE_FLAG_INHERIT != 0 {
                    if SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) == 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    guard.0.push((handle, flags));
                }
            }
        }
        Ok(guard)
    }

    fn restore(&mut self) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        let mut failure = None;
        self.0.retain(|&(handle, flags)| {
            // SAFETY: the borrowed handles are neither closed nor replaced by spawn.
            if unsafe {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags & HANDLE_FLAG_INHERIT)
            } == 0
            {
                failure.get_or_insert_with(std::io::Error::last_os_error);
                true
            } else {
                false
            }
        });
        failure.map_or(Ok(()), Err)
    }
}
#[cfg(windows)]
impl Drop for ParentStdioInheritance {
    fn drop(&mut self) {
        if self.restore().is_err() {
            // Never hide a Win32 restoration failure or expose raw OS diagnostics.
            eprintln!(
                "error [source_io]: maintenance parent stdio inheritance could not be restored"
            );
        }
    }
}

fn worker(root: &Path, catalog: &SqliteMaintenanceCatalog) -> PortResult<()> {
    let Some(queue) = SqliteMaintenanceQueue::open_existing_writable(root)? else {
        return Ok(());
    };
    let mut worker_lock = {
        let _lifecycle = QueueLock::lifecycle(root)?;
        if queue.control(None)?.paused {
            return Ok(());
        }
        let Some(lock) = QueueLock::try_worker(root)? else {
            return Ok(());
        };
        Some(lock)
    };
    let service = MaintenanceService::new(&queue, catalog, clock_ms);
    let mut idle_since = Instant::now();
    loop {
        if let Some(job) = retry_queue_busy(|| service.next_runnable(clock_ms()))? {
            retry_queue_busy(|| run_monitored(&service, root, &job.id))?;
            idle_since = Instant::now();
            continue;
        }
        let paused = retry_queue_busy(|| queue.control(None))?.paused;
        let retry_at = retry_queue_busy(|| service.next_retry_at())?;
        if paused || (retry_at.is_none() && idle_since.elapsed() >= WORKER_IDLE) {
            // A producer cannot enqueue between this final check and lock release.
            let _lifecycle = QueueLock::lifecycle(root)?;
            if retry_queue_busy(|| queue.control(None))?.paused
                || retry_queue_busy(|| service.next_retry_at())?.is_none()
            {
                drop(worker_lock.take());
                return Ok(());
            }
            idle_since = Instant::now();
        }
        // Keep the process alive for deferred work; no next CLI invocation needed.
        let sleep = retry_at
            .map(|at| Duration::from_millis(at.saturating_sub(clock_ms())).max(CONTROL_POLL))
            .unwrap_or(Duration::from_millis(200))
            .min(Duration::from_millis(200));
        std::thread::sleep(sleep);
    }
}

// Queue contention is transient too. Dropping the catalog session before retry
// preserves its original deadline and uses audit reconciliation after lost ack.
fn retry_queue_busy<T>(mut operation: impl FnMut() -> PortResult<T>) -> PortResult<T> {
    let delays = agent_session_grep_application::maintenance::RETRY_SECONDS;
    let mut attempt = 0usize;
    loop {
        match operation() {
            Err(PortError::WriterBusy(_)) => {
                std::thread::sleep(Duration::from_secs(delays[attempt.min(delays.len() - 1)]));
                attempt = attempt.saturating_add(1);
            }
            result => return result,
        }
    }
}

fn run_monitored(service: &MaintenanceService<'_>, root: &Path, id: &str) -> PortResult<()> {
    let control = MaintenanceControl::default();
    let done = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let monitor_control = control.clone();
        let monitor_done = done.clone();
        let monitor = scope.spawn(move || -> PortResult<()> {
            let result = (|| {
                let queue = SqliteMaintenanceQueue::open_existing(root)?
                    .ok_or_else(|| PortError::Backend("maintenance control unavailable".into()))?;
                while !monitor_done.load(Ordering::Acquire) {
                    let state = match queue.control(Some(id)) {
                        Ok(state) => state,
                        Err(PortError::WriterBusy(_)) => {
                            std::thread::sleep(CONTROL_POLL);
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    monitor_control
                        .cancelled
                        .store(state.cancel_requested, Ordering::Release);
                    monitor_control
                        .paused
                        .store(state.paused, Ordering::Release);
                    std::thread::sleep(CONTROL_POLL);
                }
                Ok(())
            })();
            if result.is_err() {
                monitor_control.paused.store(true, Ordering::Release);
            }
            result
        });
        let result = service.run_job(id, &control);
        done.store(true, Ordering::Release);
        let monitoring = monitor
            .join()
            .map_err(|_| PortError::Backend("maintenance control failed".into()))?;
        monitoring?;
        result.map(|_| ())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(args: &[&str]) -> Result<Request, CliError> {
        parse(
            &std::iter::once("journal")
                .chain(args.iter().copied())
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
    }
    #[cfg(windows)]
    #[test]
    fn parent_handle_inheritance_is_restored_after_spawn_failure() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{
            GetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
        };
        let file = std::fs::File::open("NUL").unwrap();
        let handle = file.as_raw_handle();
        // SAFETY: this test owns the NUL handle and never changes process stdio.
        unsafe {
            assert_ne!(
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT),
                0
            );
        }
        {
            let _guard = ParentStdioInheritance::suspend_handles(&[
                std::ptr::null_mut(),
                INVALID_HANDLE_VALUE,
                handle,
            ])
            .unwrap();
            let mut flags = 0;
            unsafe {
                assert_ne!(GetHandleInformation(handle, &mut flags), 0);
            }
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            assert!(
                Command::new("nonexistent-maintenance-worker-746f1.exe")
                    .spawn()
                    .is_err()
            );
        }
        let mut flags = 0;
        unsafe {
            assert_ne!(GetHandleInformation(handle, &mut flags), 0);
        }
        assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
    }

    #[test]
    fn budget_flag_is_registered_in_all_prefix_scanners() {
        let args: Vec<String> = [
            "--max-write-seconds",
            "7",
            "--robot",
            "--offline",
            "--request-id",
            "test-id",
            "--db",
            "test.sqlite",
            "journal",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(crate::command_name(&args), "journal");
        assert!(crate::extract_offline_flag(&args));
        assert_eq!(
            crate::extract_request_id(&args).unwrap().as_deref(),
            Some("test-id")
        );
        assert_eq!(
            crate::extract_db_flag(&args).unwrap().as_deref(),
            Some("test.sqlite")
        );
        assert_eq!(crate::bare_positionals(&args), ["journal"]);
        assert_eq!(
            protocol::parse_output_mode(&args).unwrap(),
            OutputMode::Json
        );
        assert!(crate::is_known_flag_name("--max-write-seconds"));
        let help: Vec<String> = ["--max-write-seconds", "7", "journal", "--help"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            crate::intercept_help_or_version(&help),
            Some(crate::HelpRequest::SubcommandHelp("journal".into()))
        );
    }

    #[test]
    fn parser_preserves_explicit_budget_and_rejects_invalid_combinations() {
        assert_eq!(
            request(&["submit", "--plan", "v1.abc"]).unwrap(),
            Request::Submit {
                token: "v1.abc".into(),
                budget: None
            }
        );
        assert_eq!(
            request(&["retry", "job-1", "--max-write-seconds", "31"]).unwrap(),
            Request::Retry {
                id: "job-1".into(),
                budget: Some(31)
            }
        );
        for args in [
            vec![],
            vec!["submit"],
            vec!["preview", "--plan", "x"],
            vec!["status", "--robot"],
            vec!["worker", "restart"],
            vec!["cancel"],
            vec!["retry", "x", "--max-write-seconds", "0"],
            vec!["submit", "--plan", "x", "--plan", "y"],
            vec!["retry", "x", "--max-write-seconds", "18446744073709551616"],
            vec!["submit", "--plan", "x", "--max-write-seconds", "+1"],
        ] {
            assert!(request(&args).is_err(), "{args:?}");
        }
    }
}
