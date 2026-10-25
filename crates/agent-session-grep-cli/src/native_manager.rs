//! Apply native login configuration and verify the manager's effective command.
//! Ownership, loaded configuration, and a live executable are separate facts.
//! Native output and locators remain private. No shell or detached capture runs.

use crate::{
    native_autostart::{
        AutostartChange, AutostartReceipt, ConfigurationState, ManagerRegistration,
        NativeAutostartStore, NativeLocation, SupervisorRegistration,
    },
    setup_hosts::{LocalCapture, SetupHostsErrorCode, capture_local},
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ErrorCode {
    Unavailable,
    Timeout,
    Failed,
    Busy,
    RecoveryRequired,
    Conflict,
    VerificationFailed,
}
#[derive(Debug)]
pub(crate) struct ManagerError {
    pub(crate) code: ErrorCode,
    pub(crate) observed: Option<ManagerState>,
}
impl fmt::Display for ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native manager {:?}; configuration remains recorded",
            self.code
        )
    }
}
impl From<ErrorCode> for ManagerError {
    fn from(value: ErrorCode) -> Self {
        Self {
            code: value,
            observed: None,
        }
    }
}
type Result<T> = std::result::Result<T, ManagerError>;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ManagerState {
    pub(crate) registration_present: bool,
    pub(crate) manager_loaded: bool,
    pub(crate) configured_command_verified: bool,
    pub(crate) enabled: Option<bool>,
    /// Manager state only: this is not a hash/identity proof of a live process.
    pub(crate) manager_active: Option<bool>,
    pub(crate) launch_requested: bool,
}

pub(crate) fn apply(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    run_now: bool,
    deadline: Instant,
) -> Result<ManagerState> {
    apply_with(
        store,
        change,
        registration,
        run_now,
        deadline,
        &mut execute_local,
    )
}

fn execute_local(program: &Path, args: &[OsString], deadline: Instant) -> Result<LocalCapture> {
    if !program.is_absolute() || !program.is_file() {
        return Err(ErrorCode::Unavailable.into());
    }
    let refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    capture_local(program, &refs, deadline).map_err(|error| {
        ManagerError::from(match error.code {
            SetupHostsErrorCode::ProbeTimeout => ErrorCode::Timeout,
            SetupHostsErrorCode::Io | SetupHostsErrorCode::InvalidPath => ErrorCode::Unavailable,
            _ => ErrorCode::Failed,
        })
    })
}

/// Reconcile only the owned selected registration without initiating a worker.
/// macOS defers bootstrap (RunAtLoad) until restart_owned after fence clearance.
pub(crate) fn reload_owned(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    deadline: Instant,
) -> Result<ManagerState> {
    reload_owned_with(store, change, registration, deadline, &mut execute_local)
}

pub(crate) fn reload_owned_with(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    deadline: Instant,
    execute: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture>,
) -> Result<ManagerState> {
    if !change.receipt.owned {
        return Err(ErrorCode::Conflict.into());
    }
    apply_checked(
        store,
        change,
        registration,
        StartPolicy {
            run_now: false,
            no_start: true,
            reconcile: true,
        },
        deadline,
        &mut || Ok(false),
        execute,
    )
}

/// After maintenance, start only if the caller's current identity/policy check
/// still says Running, Idle and autostart enabled. The deadline is never reset.
pub(crate) fn restart_owned_for_update(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
) -> Result<ManagerState> {
    restart_owned_in_mode(
        store,
        change,
        registration,
        deadline,
        should_run,
        &mut execute_local,
        true,
    )
}

pub(crate) fn restart_owned_with(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
    execute: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture>,
) -> Result<ManagerState> {
    restart_owned_in_mode(
        store,
        change,
        registration,
        deadline,
        should_run,
        execute,
        false,
    )
}

fn restart_owned_in_mode(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
    execute: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture>,
    update: bool,
) -> Result<ManagerState> {
    if !change.receipt.owned {
        return Err(ErrorCode::Conflict.into());
    }
    if Instant::now() >= deadline {
        return Err(ErrorCode::Timeout.into());
    }
    let run_now = should_run()?;
    if !run_now {
        let guard = store
            .manager_registration_before(&change.receipt, registration, Some(deadline))
            .map_err(native_error)?;
        guard.validate().map_err(native_error)?;
        return Ok(ManagerState {
            registration_present: true,
            manager_loaded: false,
            configured_command_verified: true,
            enabled: None,
            manager_active: None,
            launch_requested: false,
        });
    }
    let state = apply_checked(
        store,
        change,
        registration,
        StartPolicy {
            run_now,
            no_start: !run_now,
            reconcile: false,
        },
        deadline,
        should_run,
        execute,
    )?;
    if matches!(store.location(), NativeLocation::WindowsRun { .. }) && run_now {
        let guard = store
            .manager_registration_before(&change.receipt, registration, Some(deadline))
            .map_err(native_error)?;
        guard.validate().map_err(native_error)?;
        let requested = if update {
            spawn_detached_for_update(registration, deadline, should_run)?
        } else {
            spawn_detached(registration, deadline, should_run)?
        };
        if let Err(error) = guard.validate() {
            let mut error = native_error(error);
            error.observed = Some(ManagerState {
                launch_requested: requested,
                ..state
            });
            return Err(error);
        }
        return Ok(ManagerState {
            launch_requested: requested,
            ..state
        });
    }
    Ok(state)
}

/// Explicit background intent does not require enabling login registration.
/// Hash/prefix membership and current caller policy are checked before spawn.
/// The resulting supervisor inherits neither capture pipes nor updater jobs.
pub(crate) fn spawn_detached(
    registration: &SupervisorRegistration,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
) -> Result<bool> {
    spawn_detached_for_schema(registration, deadline, should_run, false)
}

/// Update recovery may restart the exact verified old21/control2 package.
/// Ordinary setup/background startup still requires the current package schema.
pub(crate) fn spawn_detached_for_update(
    registration: &SupervisorRegistration,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
) -> Result<bool> {
    spawn_detached_for_schema(registration, deadline, should_run, true)
}

fn spawn_detached_for_schema(
    registration: &SupervisorRegistration,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
    update: bool,
) -> Result<bool> {
    if Instant::now() >= deadline {
        return Err(ErrorCode::Timeout.into());
    }
    let prefix =
        crate::native_autostart::registration_prefix(registration).map_err(native_error)?;
    let install = if update {
        crate::package_installation::inspect_installation_for_update(prefix)
    } else {
        crate::package_installation::inspect_installation(prefix)
    }
    .map_err(|_| ManagerError::from(ErrorCode::VerificationFailed))?;
    if install.supervisor.as_ref().is_none_or(|(path, hash)| {
        path != &registration.supervisor || hash != &registration.supervisor_sha256
    }) {
        return Err(ErrorCode::VerificationFailed.into());
    }
    spawn_detached_checked(registration, deadline, should_run)
}
fn spawn_detached_checked(
    registration: &SupervisorRegistration,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
) -> Result<bool> {
    let file = crate::native_autostart::verify_supervisor(registration).map_err(native_error)?;
    if Instant::now() >= deadline {
        return Err(ErrorCode::Timeout.into());
    }
    if !should_run()? {
        return Ok(false);
    }
    if Instant::now() >= deadline {
        return Err(ErrorCode::Timeout.into());
    }
    detached::spawn(registration, file, deadline)?;
    Ok(true)
}

/// Acquire and retain actual OS exclusion after the maintenance fence requests
/// old-supervisor exit. The caller keeps this guard through switch, then drops it
/// before starting the next version. Busy registry reservations are not liveness.
pub(crate) fn wait_supervisor_drained(
    root: &Path,
    expected_root: agent_session_grep_adapters_sqlite::managed_locks::RootIdentity,
    deadline: Instant,
) -> Result<agent_session_grep_adapters_sqlite::managed_locks::ExclusiveGuard> {
    use agent_session_grep_adapters_sqlite::managed_locks::{
        ExclusiveGuard, LockKind, RootIdentity,
    };
    loop {
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout.into());
        }
        if RootIdentity::read(root).map_err(|_| ManagerError::from(ErrorCode::Conflict))?
            != expected_root
        {
            return Err(ErrorCode::Conflict.into());
        }
        match ExclusiveGuard::try_acquire(root, LockKind::Supervisor) {
            Ok(guard) if guard.root_identity() == expected_root => return Ok(guard),
            Ok(_) => return Err(ErrorCode::Conflict.into()),
            Err(agent_session_grep_ports::PortError::WriterBusy(_)) => std::thread::sleep(
                std::time::Duration::from_millis(10)
                    .min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(_) => return Err(ErrorCode::Conflict.into()),
        }
    }
}

fn apply_with(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    run_now: bool,
    deadline: Instant,
    execute: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture>,
) -> Result<ManagerState> {
    apply_checked(
        store,
        change,
        registration,
        StartPolicy {
            run_now,
            no_start: false,
            reconcile: true,
        },
        deadline,
        &mut || Ok(run_now),
        execute,
    )
}

#[derive(Clone, Copy)]
struct StartPolicy {
    run_now: bool,
    no_start: bool,
    reconcile: bool,
}

fn apply_checked(
    store: &NativeAutostartStore,
    change: &AutostartChange,
    registration: &SupervisorRegistration,
    policy: StartPolicy,
    deadline: Instant,
    should_run: &mut dyn FnMut() -> Result<bool>,
    execute: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture>,
) -> Result<ManagerState> {
    let StartPolicy {
        run_now,
        no_start,
        reconcile,
    } = policy;
    if Instant::now() >= deadline {
        return Err(ErrorCode::Timeout.into());
    }
    let guard = store
        .manager_registration_before(&change.receipt, registration, Some(deadline))
        .map_err(native_error)?;
    let mut run = |program: &Path, args: Vec<OsString>| -> Result<LocalCapture> {
        guard.validate().map_err(native_error)?;
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout.into());
        }
        let output = execute(program, &args, deadline)?;
        guard.validate().map_err(native_error)?;
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout.into());
        }
        Ok(output)
    };
    let state = match guard.location() {
        NativeLocation::WindowsRun { .. } => ManagerState {
            registration_present: true,
            manager_loaded: false,
            configured_command_verified: true,
            enabled: Some(true),
            manager_active: None,
            launch_requested: false,
        },
        NativeLocation::SystemdUser { .. } => {
            let systemctl = native_program("systemctl");
            let busctl = native_program("busctl");
            if change.receipt.owned && reconcile {
                success(run(
                    &systemctl,
                    words(&["--user", "--no-pager", "--no-ask-password", "daemon-reload"]),
                )?)?;
                success(run(
                    &systemctl,
                    words(&[
                        "--user",
                        "--no-pager",
                        "--no-ask-password",
                        "enable",
                        "--",
                        guard.entry(),
                    ]),
                )?)?;
            }
            // `systemctl show ExecStart` joins argv with spaces. Typed D-Bus JSON
            // preserves exact argument boundaries, including spaces and Unicode.
            let state = systemd_readback(&guard, registration, &busctl, &mut run)?;
            if state.enabled != Some(true) {
                return Err(ErrorCode::VerificationFailed.into());
            }
            if run_now && change.receipt.owned && should_run()? {
                let command = run(
                    &systemctl,
                    words(&[
                        "--user",
                        "--no-pager",
                        "--no-ask-password",
                        "--no-block",
                        "start",
                        "--",
                        guard.entry(),
                    ]),
                );
                // A pre-command deadline, changed configuration, or failed
                // spawn has no observed native start request. A returned exit
                // status proves execution, even if the manager rejected start.
                let launch_requested = command.is_ok();
                if let Err(mut error) = command.and_then(success) {
                    error.observed = Some(ManagerState {
                        manager_active: None,
                        launch_requested,
                        ..state
                    });
                    return Err(error);
                }
                ManagerState {
                    // Readback preceded the nonblocking start request; do not
                    // present that earlier active state as a post-start fact.
                    manager_active: None,
                    launch_requested: true,
                    ..state
                }
            } else {
                state
            }
        }
        NativeLocation::LaunchAgent { uid, .. } => {
            let program = Path::new("/bin/launchctl");
            let target = format!("gui/{uid}/{}", guard.entry());
            verify_gui_context(program, *uid, &mut run)?;
            let existing = run(program, words(&["print", &target]))?;
            let mut requested = false;
            if existing.success {
                let plist = success(run(program, words(&["list", "-x", guard.entry()]))?)?;
                if launchd_readback(&plist, guard.entry(), registration).is_err() {
                    let loaded = launchd_job(&plist, guard.entry())?;
                    let owned_predecessor = change.receipt.owned
                        && guard
                            .matches_owned_predecessor(|bytes| {
                                launchd_job(bytes, guard.entry())
                                    .is_ok_and(|prior| prior.arguments == loaded.arguments)
                            })
                            .map_err(native_error)?;
                    if !owned_predecessor {
                        return Err(ErrorCode::VerificationFailed.into());
                    }
                    if run_now && !reconcile && !should_run()? {
                        return Ok(ManagerState {
                            registration_present: true,
                            manager_loaded: true,
                            configured_command_verified: false,
                            enabled: None,
                            manager_active: None,
                            launch_requested: false,
                        });
                    }
                    success(run(program, words(&["bootout", &target]))?)?;
                    requested = true;
                }
            } else if change.receipt.owned {
                requested = true;
            } else {
                return Err(ErrorCode::VerificationFailed.into());
            }
            if requested && (no_start || (run_now && !should_run()?)) {
                // RunAtLoad would start a supervisor during bootstrap. Loading
                // this changed job is deferred until the caller clears its fence.
                guard.validate().map_err(native_error)?;
                return Ok(ManagerState {
                    registration_present: true,
                    manager_loaded: false,
                    configured_command_verified: false,
                    enabled: None,
                    manager_active: Some(false),
                    launch_requested: false,
                });
            }
            if requested {
                let path = guard.target().ok_or(ErrorCode::VerificationFailed)?;
                success(run(
                    program,
                    vec![
                        "bootstrap".into(),
                        format!("gui/{uid}").into(),
                        path.into_os_string(),
                    ],
                )?)?;
            }
            verify_gui_context(program, *uid, &mut run)?;
            success(run(program, words(&["print", &target]))?)?;
            let plist = success(run(program, words(&["list", "-x", guard.entry()]))?)?;
            let active = launchd_readback(&plist, guard.entry(), registration)?;
            if run_now && !requested && change.receipt.owned && should_run()? {
                success(run(program, words(&["kickstart", &target]))?)?;
                requested = true;
            }
            ManagerState {
                registration_present: true,
                manager_loaded: true,
                configured_command_verified: true,
                // A loaded job does not prove the separate disabled override.
                enabled: None,
                manager_active: if requested { None } else { active },
                launch_requested: requested,
            }
        }
    };
    guard.validate().map_err(native_error)?;
    Ok(state)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DisableSummary {
    pub(crate) registration_present: bool,
    pub(crate) configured_command_verified: bool,
    pub(crate) manager_loaded: Option<bool>,
    pub(crate) manager_active: Option<bool>,
    pub(crate) stop_requested: bool,
    pub(crate) unload_requested: bool,
}
pub(crate) struct DisabledRegistration {
    pub(crate) change: AutostartChange,
    pub(crate) summary: DisableSummary,
}

/// Remove only the exact owned current registration. Native stop/unload needs
/// an effective command proof before mutation, not just a matching job label.
/// Windows removes login startup only; an explicitly started supervisor lives.
pub(crate) fn disable_owned(
    store: &NativeAutostartStore,
    receipt: &AutostartReceipt,
    registration: &SupervisorRegistration,
    deadline: Instant,
    preflight: &mut dyn FnMut() -> Result<()>,
    execute: &mut impl FnMut(&Path, &[OsString], Instant) -> Result<LocalCapture>,
) -> Result<DisabledRegistration> {
    if Instant::now() >= deadline {
        return Err(ErrorCode::Timeout.into());
    }
    preflight()?;
    if !receipt.owned || receipt.state != ConfigurationState::Present {
        return Err(ErrorCode::Conflict.into());
    }
    let guard = store
        .manager_registration_before(receipt, registration, Some(deadline))
        .map_err(native_error)?;
    let mut run = |program: &Path, args: Vec<OsString>| -> Result<LocalCapture> {
        preflight()?;
        guard.validate().map_err(native_error)?;
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout.into());
        }
        let output = execute(program, &args, deadline)?;
        preflight()?;
        guard.validate().map_err(native_error)?;
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout.into());
        }
        Ok(output)
    };
    let mut summary = DisableSummary {
        registration_present: true,
        configured_command_verified: true,
        manager_loaded: None,
        manager_active: None,
        stop_requested: false,
        unload_requested: false,
    };
    match guard.location() {
        NativeLocation::WindowsRun { .. } => {}
        NativeLocation::SystemdUser { .. } => {
            let systemctl = native_program("systemctl");
            let busctl = native_program("busctl");
            systemd_readback(&guard, registration, &busctl, &mut run)?;
            success(run(
                &systemctl,
                words(&[
                    "--user",
                    "--no-pager",
                    "--no-ask-password",
                    "stop",
                    "--",
                    guard.entry(),
                ]),
            )?)?;
            summary.stop_requested = true;
            let stopped = systemd_readback(&guard, registration, &busctl, &mut run)?;
            if stopped.manager_active != Some(false) {
                return Err(ErrorCode::VerificationFailed.into());
            }
            summary.manager_active = Some(false);
            // Removing the enable links does not implicitly start or reload a
            // same-label replacement. The owned unit file is removed below.
            success(run(
                &systemctl,
                words(&[
                    "--user",
                    "--no-pager",
                    "--no-ask-password",
                    "--no-reload",
                    "disable",
                    "--",
                    guard.entry(),
                ]),
            )?)?;
            let disabled = systemd_readback(&guard, registration, &busctl, &mut run)?;
            if disabled.enabled != Some(false) || disabled.manager_active != Some(false) {
                return Err(ErrorCode::VerificationFailed.into());
            }
        }
        NativeLocation::LaunchAgent { uid, .. } => {
            let program = Path::new("/bin/launchctl");
            verify_gui_context(program, *uid, &mut run)?;
            let target = format!("gui/{uid}/{}", guard.entry());
            let loaded = run(program, words(&["print", &target]))?;
            if loaded.success {
                let plist = success(run(program, words(&["list", "-x", guard.entry()]))?)?;
                launchd_readback(&plist, guard.entry(), registration)?;
                success(run(program, words(&["bootout", &target]))?)?;
                summary.stop_requested = true;
                summary.unload_requested = true;
            }
            verify_gui_context(program, *uid, &mut run)?;
            // A successful whole-domain listing verifies absence without
            // interpreting an arbitrary failing label query as "not found".
            let listing = success(run(program, words(&["list"]))?)?;
            launchd_absent(&listing, guard.entry())?;
            summary.manager_loaded = Some(false);
            summary.manager_active = Some(false);
        }
    }
    guard.validate().map_err(native_error)?;
    drop(guard);
    preflight()?;
    if Instant::now() >= deadline {
        return Err(ErrorCode::Timeout.into());
    }
    let change = store.disable(receipt).map_err(native_error)?;
    preflight()?;
    if store.latest_receipt().map_err(native_error)?.as_ref() != Some(&change.receipt) {
        return Err(ErrorCode::Conflict.into());
    }
    if matches!(store.location(), NativeLocation::SystemdUser { .. }) {
        preflight()?;
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout.into());
        }
        success(execute(
            &native_program("systemctl"),
            &words(&["--user", "--no-pager", "--no-ask-password", "daemon-reload"]),
            deadline,
        )?)?;
        preflight()?;
        if store.latest_receipt().map_err(native_error)?.as_ref() != Some(&change.receipt) {
            return Err(ErrorCode::Conflict.into());
        }
        // systemd may retain an inactive unit in memory; do not claim unload.
    }
    summary.registration_present = false;
    Ok(DisabledRegistration { change, summary })
}

fn launchd_absent(bytes: &[u8], entry: &str) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| ErrorCode::VerificationFailed)?;
    let mut lines = text.lines();
    if lines.next().is_none_or(|line| {
        line.split_whitespace().collect::<Vec<_>>() != ["PID", "Status", "Label"]
    }) {
        return Err(ErrorCode::VerificationFailed.into());
    }
    for line in lines {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() != 3
            || (columns[0] != "-" && columns[0].parse::<u32>().is_err())
            || columns[1].parse::<i32>().is_err()
            || columns[2] == entry
        {
            return Err(ErrorCode::VerificationFailed.into());
        }
    }
    Ok(())
}

// This boundary deliberately owns no KILL_ON_JOB_CLOSE job. Captured native
// manager commands still use setup_hosts' cancellable process-tree machinery.
mod detached {
    use super::*;
    use std::fs::File;

    #[cfg(windows)]
    pub(super) fn spawn(
        registration: &SupervisorRegistration,
        _file: File,
        deadline: Instant,
    ) -> Result<()> {
        use std::{
            mem::size_of,
            os::windows::{
                ffi::OsStrExt,
                io::{FromRawHandle, OwnedHandle},
            },
            ptr,
        };
        use windows_sys::Win32::System::{
            JobObjects::IsProcessInJob,
            Threading::{
                CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW,
                GetCurrentProcess, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
                STARTUPINFOW, TerminateProcess, WaitForSingleObject,
            },
        };
        let mut in_job = 0;
        if unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &mut in_job) } == 0 {
            return Err(ErrorCode::Unavailable.into());
        }
        let values = [
            registration.supervisor.as_os_str(),
            OsStr::new("--db"),
            registration.catalog.as_os_str(),
        ];
        let mut line = Vec::new();
        for (index, value) in values.into_iter().enumerate() {
            if index != 0 {
                line.push(b' ' as u16);
            }
            quote(value, &mut line)?;
        }
        line.push(0);
        let executable: Vec<_> = registration
            .supervisor
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let flags = CREATE_NO_WINDOW
            | CREATE_SUSPENDED
            | if in_job != 0 {
                CREATE_BREAKAWAY_FROM_JOB
            } else {
                0
            };
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessW(
                executable.as_ptr(),
                line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                flags,
                ptr::null(),
                ptr::null(),
                &startup,
                &mut info,
            )
        } == 0
        {
            // Never silently drop BREAKAWAY when a host job prohibits it.
            return Err(ErrorCode::Unavailable.into());
        }
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
        // A nested host may prohibit breakaway from an ancestor. NULL in
        // IsProcessInJob tests every ancestor, not our parent's cleanup job.
        // Query the parent's immediate job while the child is still suspended;
        // its complete process list includes every descendant job as well.
        let outside_cleanup_job = if in_job != 0 {
            outside_parent_job(info.dwProcessId)
        } else {
            let mut child_in_job = 0;
            (unsafe { IsProcessInJob(info.hProcess, ptr::null_mut(), &mut child_in_job) != 0 })
                && child_in_job == 0
        };
        if !outside_cleanup_job {
            unsafe {
                TerminateProcess(info.hProcess, 1);
                WaitForSingleObject(
                    info.hProcess,
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(u128::from(u32::MAX)) as u32,
                );
            }
            return Err(ErrorCode::Unavailable.into());
        }
        if Instant::now() >= deadline {
            unsafe {
                TerminateProcess(info.hProcess, 1);
                WaitForSingleObject(info.hProcess, 0);
            }
            return Err(ErrorCode::Timeout.into());
        }
        if unsafe { ResumeThread(info.hThread) } == u32::MAX {
            unsafe {
                TerminateProcess(info.hProcess, 1);
                WaitForSingleObject(
                    info.hProcess,
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(u128::from(u32::MAX)) as u32,
                );
            }
            return Err(ErrorCode::Failed.into());
        }
        // Close only our handles; the verified child intentionally outlives this
        // call and its parent. No caller pipe or updater job is inherited.
        drop(thread);
        drop(process);
        Ok(())
    }
    #[cfg(windows)]
    fn outside_parent_job(child_pid: u32) -> bool {
        use std::{mem::size_of, ptr};
        use windows_sys::Win32::System::{
            JobObjects::{JobObjectBasicProcessIdList, QueryInformationJobObject},
            Threading::GetCurrentProcessId,
        };
        // Do not trust a truncated list or allocate from an unbounded job size.
        // Windows uses ULONG_PTR entries following the two DWORD counts.
        #[repr(C)]
        struct Processes {
            assigned: u32,
            returned: u32,
            ids: [usize; 4096],
        }
        let mut processes = Processes {
            assigned: 0,
            returned: 0,
            ids: [0; 4096],
        };
        let mut bytes = 0;
        if unsafe {
            QueryInformationJobObject(
                ptr::null_mut(),
                JobObjectBasicProcessIdList,
                (&mut processes as *mut Processes).cast(),
                size_of::<Processes>() as u32,
                &mut bytes,
            )
        } == 0
            || processes.assigned != processes.returned
            || processes.returned as usize > processes.ids.len()
            || bytes as usize > size_of::<Processes>()
            || (bytes as usize)
                < 2 * size_of::<u32>() + processes.returned as usize * size_of::<usize>()
        {
            return false;
        }
        let ids = &processes.ids[..processes.returned as usize];
        ids.contains(&(unsafe { GetCurrentProcessId() } as usize))
            && !ids.contains(&(child_pid as usize))
    }
    #[cfg(windows)]
    fn quote(argument: &OsStr, line: &mut Vec<u16>) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;
        line.push(b'"' as u16);
        let mut slashes = 0;
        for ch in argument.encode_wide() {
            if ch == 0 {
                return Err(ErrorCode::VerificationFailed.into());
            }
            if ch == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            line.extend(std::iter::repeat_n(
                b'\\' as u16,
                slashes * if ch == b'"' as u16 { 2 } else { 1 },
            ));
            slashes = 0;
            if ch == b'"' as u16 {
                line.push(b'\\' as u16);
            }
            line.push(ch);
        }
        line.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        line.push(b'"' as u16);
        Ok(())
    }
    #[cfg(unix)]
    pub(super) fn spawn(
        registration: &SupervisorRegistration,
        file: File,
        deadline: Instant,
    ) -> Result<()> {
        // Reuse the launcher's fd-bound exec, fully null streams and new process
        // group. No captured intermediary is launched to own or kill this group.
        drop(file);
        if Instant::now() >= deadline {
            return Err(ErrorCode::Timeout.into());
        }
        let child = agent_session_grep_launcher::spawn_verified_background(
            &registration.supervisor,
            &registration.supervisor_sha256,
            &["--db".into(), registration.catalog.as_os_str().into()],
        )
        .map_err(|_| ManagerError::from(ErrorCode::Failed))?;
        drop(child);
        Ok(())
    }
}

fn native_error(error: crate::native_autostart::AutostartError) -> ManagerError {
    use crate::native_autostart::ErrorCode as NativeCode;
    match error.code {
        NativeCode::Busy => ErrorCode::Busy,
        NativeCode::RecoveryRequired => ErrorCode::RecoveryRequired,
        NativeCode::Io | NativeCode::Unsupported => ErrorCode::Unavailable,
        _ => ErrorCode::Conflict,
    }
    .into()
}
fn verify_gui_context(
    program: &Path,
    uid: u32,
    run: &mut impl FnMut(&Path, Vec<OsString>) -> Result<LocalCapture>,
) -> Result<()> {
    let manager_uid = success(run(program, words(&["manageruid"]))?)?;
    let manager_name = success(run(program, words(&["managername"]))?)?;
    if std::str::from_utf8(&manager_uid).ok().map(str::trim) != Some(uid.to_string().as_str())
        || std::str::from_utf8(&manager_name).ok().map(str::trim) != Some("Aqua")
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    Ok(())
}
fn native_program(name: &str) -> PathBuf {
    let primary = PathBuf::from("/usr/bin").join(name);
    if primary.is_file() {
        primary
    } else {
        PathBuf::from("/bin").join(name)
    }
}
fn words(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
fn success(output: LocalCapture) -> Result<Vec<u8>> {
    if !output.success {
        return Err(ErrorCode::Failed.into());
    }
    Ok(output.stdout)
}
fn typed(value: &Value, signature: &str) -> Result<Value> {
    if value.as_object().is_none_or(|v| v.len() != 2)
        || value["type"] != signature
        || value.get("data").is_none()
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    Ok(value["data"].clone())
}
fn json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|_| ErrorCode::VerificationFailed.into())
}
fn systemd_readback(
    guard: &ManagerRegistration<'_>,
    registration: &SupervisorRegistration,
    busctl: &Path,
    run: &mut impl FnMut(&Path, Vec<OsString>) -> Result<LocalCapture>,
) -> Result<ManagerState> {
    let object = typed(
        &json(&success(run(
            busctl,
            words(&[
                "--user",
                "--json=short",
                "--no-pager",
                "call",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "LoadUnit",
                "s",
                guard.entry(),
            ]),
        )?)?)?,
        "o",
    )?;
    let object = object
        .as_array()
        .filter(|v| v.len() == 1)
        .and_then(|v| v[0].as_str())
        .ok_or(ErrorCode::VerificationFailed)?;
    if !object.starts_with("/org/freedesktop/systemd1/unit/")
        || object.len() > 1024
        || object.contains('\0')
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let bytes = success(run(
        busctl,
        words(&[
            "--user",
            "--json=short",
            "--no-pager",
            "get-property",
            "org.freedesktop.systemd1",
            object,
            "org.freedesktop.systemd1.Unit",
            "Id",
            "FragmentPath",
            "DropInPaths",
            "LoadState",
            "ActiveState",
            "UnitFileState",
            "NeedDaemonReload",
        ]),
    )?)?;
    let properties: Vec<Value> = std::str::from_utf8(&bytes)
        .map_err(|_| ErrorCode::VerificationFailed)?
        .lines()
        .map(|line| json(line.as_bytes()))
        .collect::<Result<_>>()?;
    if properties.len() != 7 {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let target = guard.target().ok_or(ErrorCode::VerificationFailed)?;
    if typed(&properties[0], "s")? != guard.entry()
        || typed(&properties[1], "s")?.as_str() != target.to_str()
        || typed(&properties[2], "as")? != serde_json::json!([])
        || typed(&properties[3], "s")? != "loaded"
        || typed(&properties[6], "b")? != false
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let state = typed(&properties[4], "s")?;
    let active = match state.as_str() {
        Some("active" | "activating" | "reloading") => true,
        Some("inactive" | "failed" | "deactivating") => false,
        _ => return Err(ErrorCode::VerificationFailed.into()),
    };
    let enabled = typed(&properties[5], "s")? == "enabled";
    let command = typed(
        &json(&success(run(
            busctl,
            words(&[
                "--user",
                "--json=short",
                "--no-pager",
                "get-property",
                "org.freedesktop.systemd1",
                object,
                "org.freedesktop.systemd1.Service",
                "ExecStart",
            ]),
        )?)?)?,
        "a(sasbttttuii)",
    )?;
    let entries = command
        .as_array()
        .filter(|v| v.len() == 1)
        .ok_or(ErrorCode::VerificationFailed)?;
    let fields = entries[0]
        .as_array()
        .filter(|v| v.len() == 10)
        .ok_or(ErrorCode::VerificationFailed)?;
    let executable = registration
        .supervisor
        .to_str()
        .ok_or(ErrorCode::VerificationFailed)?;
    let catalog = registration
        .catalog
        .to_str()
        .ok_or(ErrorCode::VerificationFailed)?;
    if fields[0] != executable
        || fields[1] != serde_json::json!([executable, "--db", catalog])
        || fields[2] != false
        || fields[3..8].iter().any(|v| v.as_u64().is_none())
        || fields[8..].iter().any(|v| v.as_i64().is_none())
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    Ok(ManagerState {
        registration_present: true,
        manager_loaded: true,
        configured_command_verified: true,
        enabled: Some(enabled),
        manager_active: Some(active),
        launch_requested: false,
    })
}

struct LaunchdJob {
    arguments: Vec<String>,
    active: Option<bool>,
}
fn launchd_readback(
    bytes: &[u8],
    entry: &str,
    registration: &SupervisorRegistration,
) -> Result<Option<bool>> {
    let job = launchd_job(bytes, entry)?;
    if job.arguments
        != [
            registration
                .supervisor
                .to_str()
                .ok_or(ErrorCode::VerificationFailed)?,
            "--db",
            registration
                .catalog
                .to_str()
                .ok_or(ErrorCode::VerificationFailed)?,
        ]
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    Ok(job.active)
}
fn launchd_job(bytes: &[u8], entry: &str) -> Result<LaunchdJob> {
    let text = std::str::from_utf8(bytes).map_err(|_| ErrorCode::VerificationFailed)?;
    // Standard plist DOCTYPE is accepted without a resolver; any entity
    // declaration is rejected. Parsing has no network/file capability.
    if text.contains("<!ENTITY") {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let doc = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            nodes_limit: 8192,
            entity_resolver: None,
        },
    )
    .map_err(|_| ErrorCode::VerificationFailed)?;
    let root = doc.root_element();
    let children: Vec<_> = root.children().filter(|n| n.is_element()).collect();
    if root.tag_name().name() != "plist"
        || root.tag_name().namespace().is_some()
        || children.len() != 1
        || children[0].tag_name().name() != "dict"
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let elements: Vec<_> = children[0].children().filter(|n| n.is_element()).collect();
    if !elements.len().is_multiple_of(2) {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let (pairs, _) = elements.as_chunks::<2>();
    let mut fields = BTreeMap::new();
    for pair in pairs {
        if pair[0].tag_name().name() != "key"
            || pair[0].children().any(|n| n.is_element())
            || pair.iter().any(|n| n.tag_name().namespace().is_some())
        {
            return Err(ErrorCode::VerificationFailed.into());
        }
        let key = pair[0].text().ok_or(ErrorCode::VerificationFailed)?;
        if fields.insert(key, pair[1]).is_some() {
            return Err(ErrorCode::VerificationFailed.into());
        }
    }
    let string = |key| -> Result<&str> {
        let node = fields.get(key).ok_or(ErrorCode::VerificationFailed)?;
        if node.tag_name().name() != "string" || node.children().any(|n| n.is_element()) {
            return Err(ErrorCode::VerificationFailed.into());
        }
        node.text()
            .ok_or_else(|| ErrorCode::VerificationFailed.into())
    };
    if string("Label")? != entry {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let args = fields
        .get("ProgramArguments")
        .ok_or(ErrorCode::VerificationFailed)?;
    if args.tag_name().name() != "array" {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let values: Vec<_> = args.children().filter(|n| n.is_element()).collect();
    if values.len() != 3
        || values.iter().any(|n| {
            n.tag_name().name() != "string"
                || n.tag_name().namespace().is_some()
                || n.children().any(|c| c.is_element())
        })
        || values[1].text() != Some("--db")
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let arguments = values
        .iter()
        .map(|node| {
            node.text()
                .map(str::to_owned)
                .ok_or_else(|| ManagerError::from(ErrorCode::VerificationFailed))
        })
        .collect::<Result<Vec<_>>>()?;
    if fields.contains_key("Program") && string("Program")? != arguments[0] {
        return Err(ErrorCode::VerificationFailed.into());
    }
    if fields
        .get("Disabled")
        .is_some_and(|n| n.tag_name().name() != "false")
    {
        return Err(ErrorCode::VerificationFailed.into());
    }
    let active = match fields.get("PID") {
        Some(node) if node.tag_name().name() == "integer" => {
            let pid = node
                .text()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or(ErrorCode::VerificationFailed)?;
            Some(pid != 0)
        }
        Some(_) => return Err(ErrorCode::VerificationFailed.into()),
        None => None,
    };
    Ok(LaunchdJob { arguments, active })
}

#[cfg(test)]
#[path = "native_manager_tests.rs"]
mod tests;
