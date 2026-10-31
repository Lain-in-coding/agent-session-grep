use std::{
    ffi::{OsStr, OsString},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    sync::{
        Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    System::{
        Console::{
            CTRL_BREAK_EVENT, CTRL_C_EVENT, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
            STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
        },
        Diagnostics::Debug::{GetThreadErrorMode, SEM_FAILCRITICALERRORS, SetThreadErrorMode},
        Threading::{
            CREATE_SUSPENDED, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, INFINITE,
            PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
            TerminateProcess, WaitForSingleObject,
        },
    },
};

use crate::{LauncherError, Result};

const STARTING: u8 = 0;
const RUNNING: u8 = 1;
const CANCELLED: u8 = 2;
const INTERRUPTED: u32 = 0xc000013a;
static PHASE: AtomicU8 = AtomicU8::new(STARTING);
static OWNER: Mutex<()> = Mutex::new(());

/// Runs process creation without the system's critical-error message box.
/// A host may start the launcher with the default error mode, where Windows
/// answers an image it cannot run with a modal dialog and CreateProcess waits
/// for a click. The thread mode makes it return the error instead; it is
/// restored at once and is not inherited, so the child keeps the caller's mode.
pub(crate) fn without_error_dialogs<T>(create: impl FnOnce() -> T) -> Result<T> {
    let mut previous = 0;
    // SAFETY: reads only the calling thread's current flags.
    let mode = unsafe { GetThreadErrorMode() } | SEM_FAILCRITICALERRORS;
    // SAFETY: both arguments are valid; this changes only the calling thread.
    if unsafe { SetThreadErrorMode(mode, &mut previous) } == 0 {
        return Err(LauncherError::ExecFailed);
    }
    struct RestoreErrorMode(u32);
    impl Drop for RestoreErrorMode {
        fn drop(&mut self) {
            // SAFETY: restores this thread's own mode, including on unwind.
            unsafe { SetThreadErrorMode(self.0, null_mut()) };
        }
    }
    let _restore = RestoreErrorMode(previous);
    Ok(create())
}

unsafe extern "system" fn handler(event: u32) -> i32 {
    if event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT {
        return 0;
    }
    let _ = PHASE.compare_exchange(STARTING, CANCELLED, Ordering::SeqCst, Ordering::SeqCst);
    // The console delivers this event to the child itself. Never rebroadcast
    // it, and never SetConsoleCtrlHandler(NULL, TRUE), which is inheritable.
    1
}

struct HandlerGuard;
impl Drop for HandlerGuard {
    fn drop(&mut self) {
        // SAFETY: removes only this module's static callback.
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 0);
        }
    }
}

fn duplicate_std(which: u32) -> Result<Option<OwnedHandle>> {
    // SAFETY: standard handles are borrowed; duplicate creates owned lifetime.
    unsafe {
        let handle = GetStdHandle(which);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Ok(None);
        }
        let current = GetCurrentProcess();
        let mut duplicated = null_mut();
        if DuplicateHandle(
            current,
            handle,
            current,
            &mut duplicated,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            return Err(LauncherError::ExecFailed);
        }
        Ok(Some(OwnedHandle::from_raw_handle(duplicated)))
    }
}

fn raw(handle: &Option<OwnedHandle>) -> HANDLE {
    handle
        .as_ref()
        .map_or(null_mut(), AsRawHandle::as_raw_handle)
}

/// MSVC argv quoting, not shell quoting. Every argument is quoted, preserving
/// empty arguments and doubling backslashes only before quotes/end quotes.
pub(crate) fn command_line(path: &Path, args: &[OsString]) -> Result<Vec<u16>> {
    let mut line = Vec::new();
    for arg in std::iter::once(path.as_os_str()).chain(args.iter().map(OsString::as_os_str)) {
        if !line.is_empty() {
            line.push(b' ' as u16);
        }
        quote_arg(arg, &mut line)?;
        if line.len() >= 32767 {
            return Err(LauncherError::ExecFailed);
        }
    }
    line.push(0);
    Ok(line)
}

fn quote_arg(arg: &OsStr, line: &mut Vec<u16>) -> Result<()> {
    line.push(b'"' as u16);
    let mut slashes = 0;
    for ch in arg.encode_wide() {
        if ch == 0 {
            return Err(LauncherError::ExecFailed);
        }
        if ch == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        let count = if ch == b'"' as u16 {
            2 * slashes + 1
        } else {
            slashes
        };
        line.extend(std::iter::repeat_n(b'\\' as u16, count));
        line.push(ch);
        slashes = 0;
    }
    line.extend(std::iter::repeat_n(b'\\' as u16, 2 * slashes));
    line.push(b'"' as u16);
    Ok(())
}

pub(super) fn launch(path: &Path, args: &[OsString]) -> Result<i32> {
    launch_observed(path, args, |_| {})
}

#[derive(Clone, Copy, PartialEq)]
enum SpawnStage {
    HandlerReady,
    ChildCreated,
    ChildResumed,
    Waiting,
}

fn launch_observed(
    path: &Path,
    args: &[OsString],
    mut observe: impl FnMut(SpawnStage),
) -> Result<i32> {
    let _owner = OWNER.try_lock().map_err(|_| LauncherError::Internal)?;
    let mut line = command_line(path, args)?;
    let executable: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let input = duplicate_std(STD_INPUT_HANDLE)?;
    let output = duplicate_std(STD_OUTPUT_HANDLE)?;
    let error = duplicate_std(STD_ERROR_HANDLE)?;
    PHASE.store(STARTING, Ordering::SeqCst);
    // SAFETY: callback is static, allocation-free and touches only an atomic.
    if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
        return Err(LauncherError::ExecFailed);
    }
    let _handler = HandlerGuard;
    observe(SpawnStage::HandlerReady);
    if PHASE.load(Ordering::SeqCst) == CANCELLED {
        return Ok(INTERRUPTED as i32);
    }
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: raw(&input),
        hStdOutput: raw(&output),
        hStdError: raw(&error),
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: terminated wide strings, writable command line and valid structs;
    // duplicated std handles remain open. Null cwd/env means inherit both.
    // No new console/group, detached flag, or ignore-Ctrl-C inheritance change.
    let created = without_error_dialogs(|| unsafe {
        CreateProcessW(
            executable.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED,
            null(),
            null(),
            &startup,
            &mut info,
        )
    })?;
    if created == 0 {
        return Err(LauncherError::ExecFailed);
    }
    // SAFETY: successful CreateProcess returns two uniquely owned handles.
    let child = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
    observe(SpawnStage::ChildCreated);
    let cancelled = PHASE.load(Ordering::SeqCst) == CANCELLED;
    // A Ctrl-C before/during creation must not start an unobserved child.
    // Resume while still STARTING: an event in that last narrow interval is
    // cancellation too; only after resume do events belong solely to the child.
    let resumed = !cancelled && unsafe { ResumeThread(thread.as_raw_handle()) } != u32::MAX;
    observe(SpawnStage::ChildResumed);
    let running = resumed
        && PHASE
            .compare_exchange(STARTING, RUNNING, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
    if !running {
        // SAFETY: this handle names only our startup child. Terminate is followed
        // by a real wait; requesting termination alone does not mean it exited.
        if unsafe { TerminateProcess(child.as_raw_handle(), INTERRUPTED) } == 0 {
            // The console may already have terminated it. Query via wait below.
            if unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
                return Err(LauncherError::Internal);
            }
        }
    }
    observe(SpawnStage::Waiting);
    // SAFETY: owned process handle remains valid until wait/status completes.
    if unsafe { WaitForSingleObject(child.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(LauncherError::Internal);
    }
    let mut status = 0;
    if unsafe { GetExitCodeProcess(child.as_raw_handle(), &mut status) } == 0 {
        return Err(LauncherError::Internal);
    }
    if !resumed && !cancelled && PHASE.load(Ordering::SeqCst) != CANCELLED {
        return Err(LauncherError::ExecFailed);
    }
    Ok(status as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Console::{
        CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    // Both tests exercise the process-global callback. Serialize test callers
    // separately without holding OWNER across the production launch function.
    static TEST_OWNER: Mutex<()> = Mutex::new(());

    #[test]
    fn error_dialog_guard_preserves_other_thread_flags_and_restores_on_unwind() {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
        };

        let original = unsafe { GetThreadErrorMode() };
        let _restore = ThreadModeRestore(original);
        struct ThreadModeRestore(u32);
        impl Drop for ThreadModeRestore {
            fn drop(&mut self) {
                unsafe { SetThreadErrorMode(self.0, null_mut()) };
            }
        }
        let expected = SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;
        assert_ne!(unsafe { SetThreadErrorMode(expected, null_mut()) }, 0);
        without_error_dialogs(|| {
            assert_eq!(
                unsafe { GetThreadErrorMode() },
                expected | SEM_FAILCRITICALERRORS
            );
        })
        .unwrap();
        assert_eq!(unsafe { GetThreadErrorMode() }, expected);
        assert!(
            std::panic::catch_unwind(|| {
                let _ = without_error_dialogs(|| panic!("test unwind"));
            })
            .is_err()
        );
        assert_eq!(unsafe { GetThreadErrorMode() }, expected);
    }

    #[test]
    fn handler_consumes_only_interrupts_and_records_startup_cancellation() {
        let _test_owner = TEST_OWNER.lock().unwrap();
        let _owner = OWNER.lock().unwrap();
        PHASE.store(STARTING, Ordering::SeqCst);
        for event in [CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, 99] {
            assert_eq!(unsafe { handler(event) }, 0);
            assert_eq!(PHASE.load(Ordering::SeqCst), STARTING);
        }
        assert_eq!(unsafe { handler(CTRL_C_EVENT) }, 1);
        assert_eq!(PHASE.load(Ordering::SeqCst), CANCELLED);
        PHASE.store(RUNNING, Ordering::SeqCst);
        assert_eq!(unsafe { handler(CTRL_BREAK_EVENT) }, 1);
        assert_eq!(PHASE.load(Ordering::SeqCst), RUNNING);
    }

    #[test]
    fn startup_interrupts_reap_real_children_and_waiting_interrupts_preserve_exit() {
        let _test_owner = TEST_OWNER.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("probe.exe");
        let status = std::process::Command::new("rustc")
            .arg("--edition=2024")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/child.rs"))
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap();
        assert!(status.success());
        let marker = temp.path().join("started");
        for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT] {
            for stage in [SpawnStage::HandlerReady, SpawnStage::ChildCreated] {
                let status = launch_observed(
                    &binary,
                    &["write-marker".into(), marker.as_os_str().into()],
                    |observed| {
                        if observed == stage {
                            assert_eq!(unsafe { handler(event) }, 1);
                        }
                    },
                )
                .unwrap();
                assert_eq!(status, INTERRUPTED as i32);
                assert!(!marker.exists(), "cancelled startup executed the probe");
            }
            // Drive the resume/publication window with a real child. Returning
            // the interruption status proves that child was terminated/reaped.
            let status = launch_observed(&binary, &["wait-for-termination".into()], |observed| {
                if observed == SpawnStage::ChildResumed {
                    assert_eq!(unsafe { handler(event) }, 1);
                }
            })
            .unwrap();
            assert_eq!(status, INTERRUPTED as i32);
            let status = launch_observed(&binary, &["exit".into(), "37".into()], |observed| {
                if observed == SpawnStage::Waiting {
                    assert_eq!(unsafe { handler(event) }, 1);
                }
            })
            .unwrap();
            assert_eq!(status, 37);
        }
    }
}
