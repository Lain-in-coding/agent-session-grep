use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::Read,
    path::{Component, Path},
};

use sha2::{Digest, Sha256};

use crate::{LauncherError, Result, metadata::MAX_METADATA_BYTES};

/// Inspect the lexical path before canonicalizing: canonicalization alone hides
/// links. Installers must publish immutable version trees; these checks do not
/// make a user-writable installation safe from its own malicious owner.
pub(crate) fn check_path(path: &Path, directory: bool, missing: LauncherError) -> Result<()> {
    if !path.is_absolute() {
        return Err(LauncherError::UnsafePath);
    }
    let mut walked = std::path::PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(LauncherError::UnsafePath);
        }
        walked.push(component);
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&walked).map_err(|_| missing)?;
        reject_link(&metadata)?;
        if (components.peek().is_some() || directory) && !metadata.is_dir() {
            return Err(LauncherError::UnsafePath);
        }
        if components.peek().is_none() && !directory && !metadata.is_file() {
            return Err(LauncherError::UnsafePath);
        }
    }
    Ok(())
}

fn reject_link(metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(LauncherError::UnsafePath);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LauncherError::UnsafePath);
        }
    }
    Ok(())
}

pub(crate) fn open_regular(path: &Path, missing: LauncherError) -> Result<File> {
    check_path(path, false, missing)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Nonblocking also avoids hanging if a regular file is swapped for a FIFO.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        // Keep the verified application pinned against writes/deletion until exit.
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path).map_err(|_| missing)?;
    let metadata = file.metadata().map_err(|_| missing)?;
    reject_link(&metadata)?;
    if !metadata.is_file() {
        return Err(LauncherError::UnsafePath);
    }
    check_path(path, false, missing)?;
    Ok(file)
}

pub(crate) fn read_metadata(
    path: &Path,
    missing: LauncherError,
    invalid: LauncherError,
) -> Result<Vec<u8>> {
    let file = open_regular(path, missing)?;
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| missing)?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(invalid);
    }
    Ok(bytes)
}

pub(crate) fn verify_app(file: &mut File, expected: &str) -> Result<()> {
    let metadata = file.metadata().map_err(|_| LauncherError::VersionMissing)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions or memory access.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 || metadata.mode() & 0o111 == 0 {
            return Err(LauncherError::UnsafePath);
        }
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut read = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| LauncherError::VersionMissing)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > metadata.len() {
            return Err(LauncherError::IntegrityFailed);
        }
        hasher.update(&buffer[..count]);
    }
    if read != metadata.len() || format!("{:x}", hasher.finalize()) != expected {
        return Err(LauncherError::IntegrityFailed);
    }
    Ok(())
}
