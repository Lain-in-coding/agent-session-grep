use std::{ffi::OsString, fs::File, path::Path};

#[cfg(not(windows))]
use crate::LauncherError;
use crate::Result;

#[cfg(windows)]
pub(crate) mod windows;

pub(crate) fn launch(path: &Path, file: &File, args: &[OsString]) -> Result<i32> {
    #[cfg(unix)]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        // No shell, environment edits, cwd changes, pipes, process groups, or
        // signal forwarding: successful exec retains the caller's process.
        // Neither exec call uses execvp's implicit /bin/sh fallback for ENOEXEC.
        let arguments: Vec<CString> = std::iter::once(path.as_os_str())
            .chain(args.iter().map(OsString::as_os_str))
            .map(|arg| CString::new(arg.as_bytes()).map_err(|_| LauncherError::ExecFailed))
            .collect::<Result<_>>()?;
        let pointers: Vec<_> = arguments
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            unsafe extern "C" {
                static mut environ: *mut *mut libc::c_char;
            }
            // Execute the descriptor whose bytes were hashed, not its pathname:
            // replacing a file or an ancestor after verification cannot select
            // another image. CLOEXEC prevents leaking the descriptor. Published
            // applications are native binaries, not interpreter scripts.
            // SAFETY: the file, argv and inherited environment remain live. As
            // for execv, callers must not concurrently mutate the C environment.
            unsafe {
                libc::fexecve(file.as_raw_fd(), pointers.as_ptr(), environ.cast());
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            use std::os::unix::fs::MetadataExt;
            // macOS has no fexecve. Reject a changed name before path-based exec;
            // the remaining native syscall window relies on immutable versions
            // owned by this user, not protection from a malicious same-user writer.
            crate::files::check_path(path, false, LauncherError::VersionMissing)?;
            let named = path.metadata().map_err(|_| LauncherError::VersionMissing)?;
            let pinned = file.metadata().map_err(|_| LauncherError::VersionMissing)?;
            if (named.dev(), named.ino()) != (pinned.dev(), pinned.ino()) {
                return Err(LauncherError::IntegrityFailed);
            }
            let executable =
                CString::new(path.as_os_str().as_bytes()).map_err(|_| LauncherError::ExecFailed)?;
            // SAFETY: executable and argv are NUL-terminated and remain live.
            unsafe {
                libc::execv(executable.as_ptr(), pointers.as_ptr());
            }
        }
        Err(LauncherError::ExecFailed)
    }
    #[cfg(windows)]
    {
        let _ = file; // Its non-write/delete-sharing handle spans CreateProcess.
        windows::launch(path, args)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, file, args);
        Err(LauncherError::TargetMismatch)
    }
}
