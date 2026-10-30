//! One prepared frame per ASG-owned helper. Only the helper owns the emission
//! gate; parent cancellation never releases a gate on behalf of a live writer.
//! The internal command is intercepted before normal CLI parsing/rendering.

use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{LockKind, RootIdentity, SharedGuard},
};
use agent_session_grep_ports::{
    PortError,
    control::{ControlId, ControlStore, PolicyEpoch, RequestIntersection},
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const INTERNAL_COMMAND: &str = "__asg_internal_emit_v1";
pub const INTERNAL_CONTROL_COMMAND: &str = "__asg_internal_control_emit_v1";
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROOT_BYTES: usize = 65536;
const MAGIC: &[u8; 8] = b"ASGEMIT1";
const CONTROL_MAGIC: &[u8; 8] = b"ASGCTL01";
const CONTROL_HEADER_BYTES: usize = 12;
const HEADER_BYTES: usize = 50;
const WRITE_READY: u8 = 1;
/// Sent after the frame write and flush complete (or the consumer closed its
/// pipe), before the helper releases anything.
const WRITE_DONE: u8 = 2;
const WRITE_WINDOW: Duration = Duration::from_millis(100);
const POLL: Duration = Duration::from_millis(1);
/// Transient control contention a helper absorbs before reporting `Blocked`.
/// It never extends the parent's own cancellation deadline.
const CONTROL_READ_BUDGET: Duration = Duration::from_secs(1);
const EXIT_POLICY: i32 = 7;
const EXIT_BLOCKED: i32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionOutcome {
    /// The OS accepted the frame, or the downstream consumer closed its pipe.
    /// This does not mean a remote consumer displayed the accepted bytes.
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionFailureKind {
    InvalidFrame,
    PolicyChanged,
    Blocked,
    StorageOrIo,
    Deadline,
    TerminationUnconfirmed,
}

/// Diagnostics are fixed classifications. Never print packet contents, paths,
/// native directory identities, child stderr or raw OS errors.
pub struct EmissionFailure {
    kind: EmissionFailureKind,
    pending: Option<Box<PendingEmission>>,
    untouched: bool,
}
impl EmissionFailure {
    pub fn kind(&self) -> EmissionFailureKind {
        self.kind
    }
    /// True only when no byte of this frame can have reached the transport:
    /// the failure happened before a helper received the frame, or the helper
    /// exited, or its confirmed termination ended the status pipe, without
    /// ever signalling that it was about to write. A zero exit without the
    /// completion marker is an anomaly and never qualifies. The caller may
    /// then answer the same request with a content-free error and keep the
    /// transport.
    pub fn output_untouched(&self) -> bool {
        self.untouched
    }
    /// A caller receiving this capability MUST close/disable this transport and
    /// retain scope_revoking for evidence until termination is confirmed. A dropped
    /// capability sends another kill request, but never claims completion.
    pub fn into_pending(self) -> Option<Box<PendingEmission>> {
        self.pending
    }
}
impl fmt::Debug for EmissionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmissionFailure")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for EmissionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "managed emission failed: {:?}", self.kind)
    }
}
impl std::error::Error for EmissionFailure {}
fn failure(kind: EmissionFailureKind) -> EmissionFailure {
    EmissionFailure {
        kind,
        pending: None,
        untouched: true,
    }
}

struct RootFile {
    _file: File,
    identity: [u8; 24],
}

/// Owns only the subprocess created for this emission and its input/status
/// tasks. It contains no shared/exclusive emission lock in the parent.
pub struct PendingEmission {
    child: Child,
    feeder: Option<JoinHandle<io::Result<()>>>,
    status_reader: Option<JoinHandle<bool>>,
    exit: Option<ExitStatus>,
    /// Set by confirmed termination: whether the status task proved a clean
    /// marker protocol. Absence of proof is never an untouched proof.
    status_clean: bool,
    _root: Option<RootFile>,
}
impl fmt::Debug for PendingEmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingEmission([owned helper])")
    }
}
impl PendingEmission {
    fn poll_exit(&mut self) -> io::Result<bool> {
        if self.exit.is_none() {
            self.exit = self.child.try_wait()?;
        }
        Ok(self.exit.is_some())
    }
    fn tasks_finished(&self) -> bool {
        self.feeder.as_ref().is_none_or(JoinHandle::is_finished)
            && self
                .status_reader
                .as_ref()
                .is_none_or(JoinHandle::is_finished)
    }
    /// Joins finished tasks: (stdin feeder succeeded, status protocol clean).
    fn join_status(&mut self) -> Option<(bool, bool)> {
        if !self.tasks_finished() {
            return None;
        }
        let feeder_ok = self
            .feeder
            .take()
            .is_none_or(|task| matches!(task.join(), Ok(Ok(()))));
        let status_clean = self
            .status_reader
            .take()
            .is_none_or(|task| matches!(task.join(), Ok(true)));
        Some((feeder_ok, status_clean))
    }
    /// Retrying termination is explicit and uses the supplied absolute deadline;
    /// no PID/host lookup, process tree kill or lock expiry is ever used.
    pub fn confirm_termination(&mut self, deadline: Instant) -> bool {
        if self.exit.is_none() {
            // Child::kill targets the owned process handle; an exit/kill race is
            // classified by try_wait, never by treating a kill request as proof.
            let _ = self.child.kill();
        }
        loop {
            if self.poll_exit().unwrap_or(false)
                && self.tasks_finished()
                && let Some((_, status_clean)) = self.join_status()
            {
                self.status_clean = status_clean;
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            pause_until(deadline);
        }
    }
}
impl Drop for PendingEmission {
    fn drop(&mut self) {
        if self.exit.is_none() {
            let _ = self.child.kill();
        }
        // Never block in Drop and never release a gate: any still-live helper
        // continues to own its gate until its actual process termination.
    }
}

fn pause_until(deadline: Instant) {
    if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        thread::sleep(POLL.min(remaining));
    }
}

/// Emit an already rendered complete frame, including its intended delimiters.
/// All setup/input/gate/output/cancellation work shares the original deadline.
/// stdout is inherited as an OS handle; no parent output thread can outlive a gate.
/// Deadline/I/O failures may follow partial OS-accepted output. Callers must
/// disable that framed transport, never append an error frame to a partial frame.
pub fn emit_frame(
    root: &Path,
    expected_root: RootIdentity,
    installation: &ControlId,
    expected_epoch: PolicyEpoch,
    frame: &[u8],
    deadline: Instant,
) -> Result<EmissionOutcome, EmissionFailure> {
    let executable =
        std::env::current_exe().map_err(|_| failure(EmissionFailureKind::StorageOrIo))?;
    emit_bound_using(
        &executable,
        EmissionTarget {
            root,
            expected_root,
            installation,
            expected_epoch,
        },
        frame,
        deadline,
        Stdio::inherit(),
    )
}

/// Emit a pre-rendered, content-free protocol/static/private-error frame.
/// Callers must never pass catalog evidence, source metadata or corpus counts.
/// No policy/root lookup or evidence gate is needed. Output and cancellation
/// still run through the supervised helper, with the same absolute deadline,
/// frame cap and close-on-partial-write contract as `emit_frame`.
pub fn emit_control_frame(
    frame: &[u8],
    deadline: Instant,
) -> Result<EmissionOutcome, EmissionFailure> {
    let executable =
        std::env::current_exe().map_err(|_| failure(EmissionFailureKind::StorageOrIo))?;
    emit_control_using(&executable, frame, deadline, Stdio::inherit())
}

// Test-visible only through this module's existing source-inclusion harness.
fn emit_control_using(
    executable: &Path,
    frame: &[u8],
    deadline: Instant,
    stdout: Stdio,
) -> Result<EmissionOutcome, EmissionFailure> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(failure(EmissionFailureKind::InvalidFrame));
    }
    let stop_at = cancellation_start(deadline)?;
    let packet = HelperPacket {
        command: INTERNAL_CONTROL_COMMAND,
        bytes: encode_control_packet(frame),
        root: None,
    };
    emit_packet_using(executable, packet, stop_at, deadline, stdout)
}

#[cfg(test)]
pub fn emit_control_using_for_test(
    executable: &Path,
    frame: &[u8],
    deadline: Instant,
    stdout: Stdio,
) -> Result<EmissionOutcome, EmissionFailure> {
    emit_control_using(executable, frame, deadline, stdout)
}

struct EmissionTarget<'a> {
    root: &'a Path,
    expected_root: RootIdentity,
    installation: &'a ControlId,
    expected_epoch: PolicyEpoch,
}

// The production entry requires the response's captured root identity. Tests
// use the real CLI binary with a controlled sink and freshly captured identity.
#[cfg(test)]
pub fn emit_using(
    executable: &Path,
    root: &Path,
    installation: &ControlId,
    expected_epoch: PolicyEpoch,
    frame: &[u8],
    deadline: Instant,
    stdout: Stdio,
) -> Result<EmissionOutcome, EmissionFailure> {
    let expected_root =
        RootIdentity::read(root).map_err(|_| failure(EmissionFailureKind::StorageOrIo))?;
    emit_bound_using(
        executable,
        EmissionTarget {
            root,
            expected_root,
            installation,
            expected_epoch,
        },
        frame,
        deadline,
        stdout,
    )
}

fn emit_bound_using(
    executable: &Path,
    target: EmissionTarget<'_>,
    frame: &[u8],
    deadline: Instant,
    stdout: Stdio,
) -> Result<EmissionOutcome, EmissionFailure> {
    let EmissionTarget {
        root,
        expected_root,
        installation,
        expected_epoch,
    } = target;
    if frame.len() > MAX_FRAME_BYTES {
        return Err(failure(EmissionFailureKind::InvalidFrame));
    }
    let stop_at = cancellation_start(deadline)?;
    let root_path = root
        .canonicalize()
        .map_err(|_| failure(EmissionFailureKind::StorageOrIo))?;
    let root_file = open_root(&root_path).map_err(|_| failure(EmissionFailureKind::StorageOrIo))?;
    if RootIdentity::read(&root_path).ok() != Some(expected_root) {
        return Err(failure(EmissionFailureKind::PolicyChanged));
    }
    let packet = HelperPacket {
        command: INTERNAL_COMMAND,
        bytes: encode_packet(
            &root_path,
            installation,
            expected_epoch,
            frame,
            root_file.identity,
        )?,
        root: Some(root_file),
    };
    emit_packet_using(executable, packet, stop_at, deadline, stdout)
}

fn cancellation_start(deadline: Instant) -> Result<Instant, EmissionFailure> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| failure(EmissionFailureKind::Deadline))?;
    if remaining.is_zero() {
        return Err(failure(EmissionFailureKind::Deadline));
    }
    // Reserve confirmation time *within* the original budget. It is not a new
    // timeout after failure. OS nonprogress is returned as unconfirmed.
    let reserve = Duration::from_millis(100).min(remaining / 4);
    deadline
        .checked_sub(reserve)
        .ok_or_else(|| failure(EmissionFailureKind::Deadline))
}

struct HelperPacket {
    command: &'static str,
    bytes: Vec<u8>,
    root: Option<RootFile>,
}

fn emit_packet_using(
    executable: &Path,
    packet: HelperPacket,
    stop_at: Instant,
    deadline: Instant,
    stdout: Stdio,
) -> Result<EmissionOutcome, EmissionFailure> {
    if Instant::now() >= stop_at {
        return Err(failure(EmissionFailureKind::Deadline));
    }
    let executable = executable
        .canonicalize()
        .map_err(|_| failure(EmissionFailureKind::StorageOrIo))?;
    let mut command = Command::new(executable);
    command
        .arg(packet.command)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW without DETACHED_PROCESS retains explicitly inherited
        // stdout/stderr handles and does not create an interactive console.
        command.creation_flags(0x0800_0000);
    }
    let child = command
        .spawn()
        .map_err(|_| failure(EmissionFailureKind::StorageOrIo))?;
    let mut process = PendingEmission {
        child,
        feeder: None,
        status_reader: None,
        exit: None,
        status_clean: false,
        _root: packet.root,
    };
    let Some(mut input) = process.child.stdin.take() else {
        return cancel(process, None, deadline, EmissionFailureKind::StorageOrIo);
    };
    let Some(mut status) = process.child.stderr.take() else {
        return cancel(process, None, deadline, EmissionFailureKind::StorageOrIo);
    };
    // At most two markers are ever sent, so the sender never blocks.
    let (sender, markers) = mpsc::sync_channel(2);
    process.status_reader =
        match thread::Builder::new()
            .name("asg-emit-status".into())
            .spawn(move || {
                // A no-write proof requires clean EOF before READY. Status I/O
                // errors, malformed bytes, or another marker sequence never
                // authorize treating stdout as untouched.
                let mut seen = 0;
                loop {
                    let mut byte = [0];
                    match status.read(&mut byte) {
                        Ok(0) => return seen != 1,
                        Ok(1) if seen == 0 && byte[0] == WRITE_READY => {}
                        Ok(1) if seen == 1 && byte[0] == WRITE_DONE => {}
                        _ => return false,
                    }
                    seen += 1;
                    if sender.send(byte[0]).is_err() {
                        return false;
                    }
                    if seen == 2 {
                        // A successful frame ends the status protocol here.
                        return true;
                    }
                }
            }) {
            Ok(task) => Some(task),
            Err(_) => return cancel(process, None, deadline, EmissionFailureKind::StorageOrIo),
        };
    process.feeder = match thread::Builder::new()
        .name("asg-emit-input".into())
        .spawn(move || {
            // The child consumes all bytes and EOF before acquiring its gate. This
            // task never touches inherited stdout. Killing the child closes its
            // input reader; completion is checked before cancellation is confirmed.
            input.write_all(&packet.bytes)?;
            drop(input);
            Ok(())
        }) {
        Ok(task) => Some(task),
        Err(_) => return cancel(process, None, deadline, EmissionFailureKind::StorageOrIo),
    };
    supervise(process, markers, stop_at, deadline)
}

/// Status markers observed from one helper.
#[derive(Default)]
struct Markers {
    ready: bool,
    done: bool,
}
impl Markers {
    fn drain(&mut self, markers: &Receiver<u8>) {
        while let Ok(marker) = markers.try_recv() {
            match marker {
                WRITE_READY => self.ready = true,
                WRITE_DONE => self.done = true,
                _ => {}
            }
        }
    }
}

fn supervise(
    mut process: PendingEmission,
    markers: Receiver<u8>,
    stop_at: Instant,
    deadline: Instant,
) -> Result<EmissionOutcome, EmissionFailure> {
    let mut seen = Markers::default();
    let mut write_end = None;
    loop {
        seen.drain(&markers);
        if seen.ready && write_end.is_none() {
            write_end = Some(Instant::now() + WRITE_WINDOW);
        }
        // The write window bounds only output. Once the OS accepted the
        // complete frame, helper teardown is never a failed emission.
        let cancel_at = match write_end {
            Some(end) if !seen.done => stop_at.min(end),
            _ => stop_at,
        };
        match process.poll_exit() {
            Ok(true) if process.tasks_finished() => {
                // The status pipe is closed: every marker has been forwarded.
                seen.drain(&markers);
                let code = process.exit.and_then(|s| s.code());
                let (feeder_ok, status_clean) = process.join_status().unwrap_or((false, false));
                // Only DONE proves the OS accepted the complete frame. A zero
                // exit without it is a protocol anomaly, never a completion.
                if seen.done {
                    return Ok(EmissionOutcome::Completed);
                }
                let kind = match code {
                    Some(EXIT_POLICY) => EmissionFailureKind::PolicyChanged,
                    Some(EXIT_BLOCKED) => EmissionFailureKind::Blocked,
                    Some(2) => EmissionFailureKind::InvalidFrame,
                    _ => EmissionFailureKind::StorageOrIo,
                };
                return Err(EmissionFailure {
                    kind,
                    pending: None,
                    untouched: !seen.ready && status_clean && feeder_ok && code != Some(0),
                });
            }
            Ok(true) if Instant::now() < deadline => {
                // An exited helper releases nothing further; its stdin and
                // status tasks finish with the closed pipes.
                pause_until(deadline);
                continue;
            }
            Err(_) => {
                return cancel(
                    process,
                    Some((&markers, seen)),
                    deadline,
                    EmissionFailureKind::StorageOrIo,
                );
            }
            _ => {}
        }
        if Instant::now() >= cancel_at {
            return cancel(
                process,
                Some((&markers, seen)),
                deadline,
                EmissionFailureKind::Deadline,
            );
        }
        pause_until(cancel_at);
    }
}
/// Terminates the helper within the original deadline. A frame the helper
/// reported fully written is complete even if its teardown had to be killed.
fn cancel(
    mut process: PendingEmission,
    markers: Option<(&Receiver<u8>, Markers)>,
    deadline: Instant,
    reason: EmissionFailureKind,
) -> Result<EmissionOutcome, EmissionFailure> {
    if process.confirm_termination(deadline) {
        // Termination closed the status pipe, so the markers are final. A
        // helper given no frame (no receiver yet) cannot have written one.
        let given_frame = markers.is_some();
        let seen = markers.map_or_else(Markers::default, |(receiver, mut seen)| {
            seen.drain(receiver);
            seen
        });
        if seen.done {
            return Ok(EmissionOutcome::Completed);
        }
        let exited_zero = process.exit.and_then(|s| s.code()) == Some(0);
        let status_clean = process.status_clean;
        Err(EmissionFailure {
            kind: reason,
            pending: None,
            untouched: !seen.ready && (!given_frame || (status_clean && !exited_zero)),
        })
    } else {
        Err(EmissionFailure {
            kind: EmissionFailureKind::TerminationUnconfirmed,
            pending: Some(Box::new(process)),
            untouched: false,
        })
    }
}

/// Returns None for ordinary CLI arguments. The hook must exit with this code
/// without rendering protocol envelopes or printing raw input/errors.
pub fn intercept(args: &[OsString]) -> Option<i32> {
    let command = args.first()?;
    let control = command == OsStr::new(INTERNAL_CONTROL_COMMAND);
    if !control && command != OsStr::new(INTERNAL_COMMAND) {
        return None;
    }
    if args.len() != 1 {
        return Some(2);
    }
    Some(if control { control_helper() } else { helper() })
}

fn control_helper() -> i32 {
    let frame = match decode_control_packet(&mut io::stdin().lock()) {
        Ok(frame) => frame,
        Err(()) => return 2,
    };
    write_frame(&frame)
}

fn helper() -> i32 {
    let request = match decode_packet(&mut io::stdin().lock()) {
        Ok(request) => request,
        Err(()) => return 2,
    };
    let root = match open_root(&request.root) {
        Ok(root) => root,
        Err(_) => return EXIT_POLICY,
    };
    if root.identity != request.root_identity {
        return EXIT_POLICY;
    }
    let gate_deadline = Instant::now() + Duration::from_millis(250);
    let gate = loop {
        match SharedGuard::try_acquire(&request.root, LockKind::PolicyEmission) {
            Ok(gate) => break gate,
            Err(PortError::WriterBusy(_)) if Instant::now() < gate_deadline => {
                pause_until(gate_deadline)
            }
            Err(_) => return EXIT_BLOCKED,
        }
    };
    if RootIdentity::read(&request.root).ok() != Some(gate.root_identity()) {
        return EXIT_POLICY;
    }
    // A transient refusal (another handle's checkpoint, or a sidecar whose
    // delete is pending) is not a policy change. Retry it briefly; if it
    // persists, report Blocked, which callers treat as retryable. Every other
    // failure still withholds the frame as a policy change.
    let budget_end = Instant::now() + CONTROL_READ_BUDGET;
    let (control, policy) = loop {
        let attempt = SqliteControlStore::open_current_read_only(&request.root).and_then(|store| {
            let policy = store.read_policy(RequestIntersection::Selected)?;
            Ok((store, policy))
        });
        match attempt {
            Ok(opened) => break opened,
            Err(PortError::WriterBusy(_)) if Instant::now() < budget_end => thread::sleep(
                Duration::from_millis(5).min(budget_end.saturating_duration_since(Instant::now())),
            ),
            Err(PortError::WriterBusy(_)) => return EXIT_BLOCKED,
            Err(_) => return EXIT_POLICY,
        }
    };
    if policy.policy_epoch != request.epoch || policy.installation_id != request.installation {
        return EXIT_POLICY;
    }
    if policy.emission_blocked() {
        return EXIT_BLOCKED;
    }
    // Recheck the held native directory against the current locator after the
    // control open; a replaced/retargeted root never authorizes the old frame.
    if !open_root(&request.root).is_ok_and(|current| current.identity == root.identity)
        || RootIdentity::read(&request.root).ok() != Some(gate.root_identity())
    {
        return EXIT_POLICY;
    }
    let code = write_frame(&request.frame);
    // The output operation has completed (or returned EPIPE) before the guard
    // can drop. Killing a stalled helper releases its guard only at actual exit.
    drop(control);
    drop(gate);
    drop(root);
    code
}

fn write_frame(frame: &[u8]) -> i32 {
    // Content-free status bytes on a separate private pipe: READY before the
    // write and DONE after it completed. The parent caps only the span between
    // them and owns cancellation.
    if io::stderr().lock().write_all(&[WRITE_READY]).is_err() {
        return 5;
    }
    let stdout = io::stdout();
    let mut sink = stdout.lock();
    let result = sink.write_all(frame).and_then(|()| sink.flush());
    drop(sink);
    let code = match result {
        Ok(()) => 0,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
        Err(_) => 5,
    };
    if code == 0 {
        // A parent that already stopped reading status loses only this marker.
        let _ = io::stderr().lock().write_all(&[WRITE_DONE]);
    }
    code
}

fn encode_control_packet(frame: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CONTROL_HEADER_BYTES + frame.len());
    bytes.extend_from_slice(CONTROL_MAGIC);
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

fn decode_control_packet(input: &mut impl Read) -> Result<Vec<u8>, ()> {
    let mut header = [0u8; CONTROL_HEADER_BYTES];
    input.read_exact(&mut header).map_err(|_| ())?;
    if &header[..8] != CONTROL_MAGIC {
        return Err(());
    }
    let len = u32::from_le_bytes(header[8..12].try_into().map_err(|_| ())?) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(());
    }
    let mut frame = vec![0u8; len];
    input.read_exact(&mut frame).map_err(|_| ())?;
    if input.read(&mut [0u8; 1]).map_err(|_| ())? != 0 {
        return Err(());
    }
    Ok(frame)
}

#[cfg(test)]
pub fn control_packet_for_test(frame: &[u8]) -> Vec<u8> {
    assert!(frame.len() <= MAX_FRAME_BYTES);
    encode_control_packet(frame)
}

struct Request {
    root: PathBuf,
    installation: ControlId,
    epoch: PolicyEpoch,
    root_identity: [u8; 24],
    frame: Vec<u8>,
}
fn encode_packet(
    root: &Path,
    installation: &ControlId,
    epoch: PolicyEpoch,
    frame: &[u8],
    identity: [u8; 24],
) -> Result<Vec<u8>, EmissionFailure> {
    let path = encode_path(root);
    if path.is_empty() || path.len() > MAX_ROOT_BYTES || frame.len() > MAX_FRAME_BYTES {
        return Err(failure(EmissionFailureKind::InvalidFrame));
    }
    let mut bytes =
        Vec::with_capacity(HEADER_BYTES + path.len() + installation.as_str().len() + frame.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(installation.as_str().len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&epoch.get().to_le_bytes());
    bytes.extend_from_slice(&identity);
    bytes.extend_from_slice(&path);
    bytes.extend_from_slice(installation.as_str().as_bytes());
    bytes.extend_from_slice(frame);
    Ok(bytes)
}
fn decode_packet(input: &mut impl Read) -> Result<Request, ()> {
    let mut header = [0u8; HEADER_BYTES];
    input.read_exact(&mut header).map_err(|_| ())?;
    if &header[..8] != MAGIC {
        return Err(());
    }
    let root_len = u32::from_le_bytes(header[8..12].try_into().map_err(|_| ())?) as usize;
    let installation_len = u16::from_le_bytes(header[12..14].try_into().map_err(|_| ())?) as usize;
    let frame_len = u32::from_le_bytes(header[14..18].try_into().map_err(|_| ())?) as usize;
    let epoch = PolicyEpoch::new(i64::from_le_bytes(
        header[18..26].try_into().map_err(|_| ())?,
    ))
    .map_err(|_| ())?;
    let root_identity = header[26..50].try_into().map_err(|_| ())?;
    if root_len == 0
        || root_len > MAX_ROOT_BYTES
        || installation_len == 0
        || installation_len > 128
        || frame_len > MAX_FRAME_BYTES
    {
        return Err(());
    }
    let mut body = vec![0u8; root_len + installation_len + frame_len];
    input.read_exact(&mut body).map_err(|_| ())?;
    if input.read(&mut [0u8; 1]).map_err(|_| ())? != 0 {
        return Err(());
    }
    let root = decode_path(&body[..root_len])?;
    if !root.is_absolute() {
        return Err(());
    }
    let installation = ControlId::parse(
        std::str::from_utf8(&body[root_len..root_len + installation_len]).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    Ok(Request {
        root,
        installation,
        epoch,
        root_identity,
        frame: body[root_len + installation_len..].to_vec(),
    })
}

#[cfg(unix)]
fn encode_path(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}
#[cfg(unix)]
fn decode_path(bytes: &[u8]) -> Result<PathBuf, ()> {
    use std::os::unix::ffi::OsStringExt;
    if bytes.contains(&0) {
        return Err(());
    }
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}
#[cfg(windows)]
fn encode_path(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}
#[cfg(windows)]
fn decode_path(bytes: &[u8]) -> Result<PathBuf, ()> {
    use std::os::windows::ffi::OsStringExt;
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let (pairs, _) = bytes.as_chunks::<2>();
    let units = pairs
        .iter()
        .map(|[low, high]| u16::from_le_bytes([*low, *high]))
        .collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(());
    }
    Ok(PathBuf::from(OsString::from_wide(&units)))
}

#[cfg(unix)]
fn open_root(path: &Path) -> io::Result<RootFile> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::other("invalid emission root"));
    }
    let mut identity = [0u8; 24];
    identity[..8].copy_from_slice(&metadata.dev().to_le_bytes());
    identity[8..16].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(RootFile {
        _file: file,
        identity,
    })
}
#[cfg(windows)]
fn open_root(path: &Path) -> io::Result<RootFile> {
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
        GetFileInformationByHandleEx,
    };
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other("invalid emission root"));
    }
    let mut information = std::mem::MaybeUninit::<FILE_ID_INFO>::zeroed();
    // SAFETY: live directory handle; output is correctly sized/aligned FILE_ID_INFO.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            information.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful call initialized the requested FILE_ID_INFO structure.
    let information = unsafe { information.assume_init() };
    let mut identity = [0u8; 24];
    identity[..8].copy_from_slice(&information.VolumeSerialNumber.to_le_bytes());
    identity[8..].copy_from_slice(&information.FileId.Identifier);
    Ok(RootFile {
        _file: file,
        identity,
    })
}

#[cfg(test)]
pub fn packet_for_test(
    root: &Path,
    installation: &ControlId,
    epoch: PolicyEpoch,
    frame: &[u8],
) -> Vec<u8> {
    let root = root.canonicalize().unwrap();
    let file = open_root(&root).unwrap();
    encode_packet(&root, installation, epoch, frame, file.identity).unwrap()
}
