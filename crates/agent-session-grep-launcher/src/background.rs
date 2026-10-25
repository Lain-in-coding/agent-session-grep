//! Child lifetime for the supervisor. All launches consume a verified image;
//! no source data, environment overrides or terminal handles are introduced.
use crate::{LauncherError, Result};
use std::{ffi::OsString, fs::File, path::Path};

pub struct BackgroundChild {
    #[cfg(unix)]
    process: std::process::Child,
    #[cfg(windows)]
    process: std::os::windows::io::OwnedHandle,
    id: u32,
    exit: Option<i32>,
}
impl BackgroundChild {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn try_wait(&mut self) -> Result<Option<i32>> {
        if self.exit.is_some() {
            return Ok(self.exit);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            self.exit = self
                .process
                .try_wait()
                .map_err(|_| LauncherError::IoFailed)?
                .map(|s| s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0)));
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{
                Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
                System::Threading::{GetExitCodeProcess, WaitForSingleObject},
            };
            // SAFETY: this is the live process handle returned by our spawn.
            match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => return Ok(None),
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                        return Err(LauncherError::IoFailed);
                    }
                    self.exit = Some(code as i32);
                }
                _ => return Err(LauncherError::IoFailed),
            }
        }
        Ok(self.exit)
    }
}

pub(crate) fn spawn(path: &Path, file: File, args: &[OsString]) -> Result<BackgroundChild> {
    #[cfg(windows)]
    {
        use std::{
            mem::size_of,
            os::windows::{
                ffi::OsStrExt,
                io::{FromRawHandle, OwnedHandle},
            },
            ptr::null,
        };
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CreateProcessW, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOW,
        };
        let mut line = crate::process::windows::command_line(path, args)?;
        let executable: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        // No inheritable handle crosses this boundary, including redirected
        // caller pipes. The verified file's nonsharing handle stays open until
        // CreateProcess has selected its executable image.
        let created = unsafe {
            CreateProcessW(
                executable.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_NO_WINDOW,
                null(),
                null(),
                &startup,
                &mut info,
            )
        };
        if created == 0 {
            return Err(LauncherError::ExecFailed);
        }
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        drop(unsafe { OwnedHandle::from_raw_handle(info.hThread) });
        drop(file);
        Ok(BackgroundChild {
            process,
            id: info.dwProcessId,
            exit: None,
        })
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::{
            os::unix::process::CommandExt,
            process::{Command, Stdio},
        };
        let arguments = ExecArguments::new(path, args)?;
        #[cfg(not(target_os = "linux"))]
        let executable = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| LauncherError::ExecFailed)?
        };
        let mut command = Command::new(path);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        // Everything needed below is allocated before fork. The child closure
        // only invokes async-signal-safe native functions and reports errno.
        unsafe {
            command.pre_exec(move || {
                #[cfg(target_os = "linux")]
                {
                    unsafe extern "C" {
                        static mut environ: *mut *mut libc::c_char;
                    }
                    libc::fexecve(file.as_raw_fd(), arguments.as_ptr(), environ.cast());
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
                    let mut pinned = std::mem::MaybeUninit::<libc::stat>::uninit();
                    if libc::stat(executable.as_ptr(), named.as_mut_ptr()) != 0
                        || libc::fstat(file.as_raw_fd(), pinned.as_mut_ptr()) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    let named = named.assume_init();
                    let pinned = pinned.assume_init();
                    if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino) {
                        return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
                    }
                    libc::execv(executable.as_ptr(), arguments.as_ptr());
                }
                Err(std::io::Error::last_os_error())
            });
        }
        let process = command.spawn().map_err(|_| LauncherError::ExecFailed)?;
        let id = process.id();
        Ok(BackgroundChild {
            process,
            id,
            exit: None,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, file, args);
        Err(LauncherError::TargetMismatch)
    }
}

#[cfg(unix)]
struct ExecArguments {
    _strings: Vec<std::ffi::CString>,
    pointers: Vec<*const libc::c_char>,
}
#[cfg(unix)]
impl ExecArguments {
    fn new(path: &Path, args: &[OsString]) -> Result<Self> {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let strings: Vec<_> = std::iter::once(path.as_os_str())
            .chain(args.iter().map(OsString::as_os_str))
            .map(|arg| CString::new(arg.as_bytes()).map_err(|_| LauncherError::ExecFailed))
            .collect::<Result<_>>()?;
        let pointers = strings
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        Ok(Self {
            _strings: strings,
            pointers,
        })
    }
    fn as_ptr(&self) -> *const *const libc::c_char {
        self.pointers.as_ptr()
    }
}
// SAFETY: pointers refer exclusively to immutable owned CString allocations.
// Moving/sharing this container never moves the referenced bytes, and nothing
// mutates them. The container outlives exec in the child closure.
#[cfg(unix)]
unsafe impl Send for ExecArguments {}
#[cfg(unix)]
unsafe impl Sync for ExecArguments {}
