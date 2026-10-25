//! Stable, offline launcher protocol v1. It knows installation identity only;
//! it neither opens a catalog nor reads host configuration or provider history.
//! Package assembly copies the launcher binary to both public command names.

mod background;
mod error;
mod files;
pub mod metadata;
mod process;

use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use serde::Serialize;

pub use background::BackgroundChild;
pub use error::{LauncherError, Result};
pub use metadata::{CurrentPointer, ReleaseMetadata};

/// Successful verification pins an application file. No unchecked constructor
/// or mutable metadata is exposed to the process boundary.
pub struct VerifiedApplication {
    path: PathBuf,
    file: File,
    pointer: CurrentPointer,
    release: ReleaseMetadata,
}

#[derive(Debug, Serialize)]
pub struct LauncherInfo<'a> {
    pub schema: &'static str,
    pub launcher_protocol: u32,
    pub target: &'static str,
    pub generation: u64,
    pub version: &'a str,
    pub source_commit: &'a str,
    pub app_sha256: &'a str,
    pub catalog_schema: u32,
    pub control_schema: u32,
}

impl VerifiedApplication {
    pub fn info(&self) -> LauncherInfo<'_> {
        LauncherInfo {
            schema: "asg.launcher-info/v1",
            launcher_protocol: metadata::LAUNCHER_PROTOCOL,
            target: metadata::BUILD_TARGET,
            generation: self.pointer.generation.get(),
            version: &self.release.version,
            source_commit: &self.release.source_commit,
            app_sha256: &self.release.app_sha256,
            catalog_schema: self.release.catalog_schema.get(),
            control_schema: self.release.control_schema.get(),
        }
    }

    /// Replaces the calling process on Unix; waits on Windows. Windows codes
    /// use the complete 32-bit bit pattern, including codes above i32::MAX.
    pub fn launch(self, args: &[OsString]) -> Result<i32> {
        process::launch(&self.path, &self.file, args)
    }

    /// Launch only this verified image with no inherited terminal streams.
    /// The returned handle refers only to this child; it never resolves a PID.
    pub fn spawn_background(self, args: &[OsString]) -> Result<BackgroundChild> {
        background::spawn(&self.path, self.file, args)
    }
}

pub fn verify_installation(prefix: &Path) -> Result<VerifiedApplication> {
    files::check_path(prefix, true, LauncherError::NotInstalled)?;
    let prefix = prefix
        .canonicalize()
        .map_err(|_| LauncherError::NotInstalled)?;
    let pointer = CurrentPointer::parse(&files::read_metadata(
        &prefix.join("current.json"),
        LauncherError::NotInstalled,
        LauncherError::PointerInvalid,
    )?)?;
    let version_dir = prefix.join(&pointer.dir);
    files::check_path(&version_dir, true, LauncherError::VersionMissing)?;
    let resolved = version_dir
        .canonicalize()
        .map_err(|_| LauncherError::VersionMissing)?;
    if !resolved.starts_with(prefix.join("versions")) {
        return Err(LauncherError::UnsafePath);
    }
    let release = ReleaseMetadata::parse(
        &files::read_metadata(
            &version_dir.join("release.json"),
            LauncherError::VersionMissing,
            LauncherError::ReleaseInvalid,
        )?,
        &pointer,
    )?;
    let path = version_dir.join(&pointer.app);
    let mut file = files::open_regular(&path, LauncherError::VersionMissing)?;
    files::verify_app(&mut file, &pointer.app_sha256)?;
    Ok(VerifiedApplication {
        path,
        file,
        pointer,
        release,
    })
}

/// Spawn an immutable package helper whose expected digest was supplied by the
/// verified installation manifest. This never searches PATH or follows links.
pub fn spawn_verified_background(
    path: &Path,
    expected_sha256: &str,
    args: &[OsString],
) -> Result<BackgroundChild> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(LauncherError::IntegrityFailed);
    }
    let mut file = files::open_regular(path, LauncherError::VersionMissing)?;
    files::verify_app(&mut file, expected_sha256)?;
    background::spawn(path, file, args)
}

/// Production discovery uses the executable location, never argv[0], PATH,
/// current directory, a host setting, or an environment override.
pub fn verify_current_executable() -> Result<VerifiedApplication> {
    let executable = std::env::current_exe().map_err(|_| LauncherError::NotInstalled)?;
    files::check_path(&executable, false, LauncherError::NotInstalled)?;
    let parent = executable.parent().ok_or(LauncherError::NotInstalled)?;
    verify_installation(parent)
}

pub fn run(args: &[OsString], stdout: &mut impl Write) -> Result<i32> {
    let app = verify_current_executable()?;
    // Only a standalone launcher request is consumed. The same token inside
    // application arguments (including after --) remains application data.
    if args.len() == 1 && args[0] == "--asg-launcher-info" {
        serde_json::to_writer(&mut *stdout, &app.info()).map_err(|_| LauncherError::IoFailed)?;
        stdout
            .write_all(b"\n")
            .map_err(|_| LauncherError::IoFailed)?;
        stdout.flush().map_err(|_| LauncherError::IoFailed)?;
        Ok(0)
    } else {
        app.launch(args)
    }
}
