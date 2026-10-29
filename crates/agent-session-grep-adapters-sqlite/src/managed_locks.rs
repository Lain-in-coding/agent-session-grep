//! OS capabilities for cooperating managed-history processes, separate from
//! the catalog writer lease. Callers own retry/deadline and admission policy.
//! A try call can also return busy while another thread of this process holds
//! or is acquiring the same root and lock kind; other keys never cause busy.
//!
//! Lock files stay empty and are never removed or replaced, including on Drop.
//! Every guard owns an independently opened handle. Shared guards cover one
//! emission frame or the entire lifetime of a catalog/control connection; an exclusive
//! guard proves drain only while it remains alive. Never upgrade a shared guard
//! in place or clear a durable intent based on time or a PID.

use agent_session_grep_ports::{
    PortError, PortResult,
    control::{ControlId, PhysicalRootBinding},
};
use fs4::fs_std::FileExt;
#[cfg(any(windows, test))]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    fmt,
    fs::{self, File},
    io,
    path::Path,
    sync::{Mutex, OnceLock},
};

#[cfg(test)]
thread_local! {
    static FAIL_PUBLICATION_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EXIT_PUBLICATION_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_publication_sync() {
    FAIL_PUBLICATION_SYNC.with(|slot| slot.set(true));
}

#[cfg(test)]
pub(crate) fn exit_next_publication_sync() {
    EXIT_PUBLICATION_SYNC.with(|slot| slot.set(true));
}

fn publication_sync_boundary() -> io::Result<()> {
    #[cfg(test)]
    if EXIT_PUBLICATION_SYNC.with(|slot| slot.replace(false)) {
        std::process::exit(87);
    }
    #[cfg(test)]
    if FAIL_PUBLICATION_SYNC.with(|slot| slot.replace(false)) {
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    Ok(())
}

/// Opaque job identifier, 1..=64 ASCII letters, digits, underscores or hyphens.
/// Its filename uses hex encoding so Windows case folding cannot merge jobs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct JobLockKey(String);

impl JobLockKey {
    pub fn parse(value: &str) -> PortResult<Self> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(invalid());
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for JobLockKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JobLockKey([private])")
    }
}

/// Separate lock domains; emission and catalog/control handles allow sharing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LockKind {
    PolicyOwner,
    PolicyEmission,
    ControlCreate,
    CatalogHandles,
    ControlHandles,
    HistoryReaders,
    Background,
    Supervisor,
    MaintenanceJob(JobLockKey),
}

impl LockKind {
    fn filename(&self) -> String {
        match self {
            Self::PolicyOwner => "policy-owner.lock".into(),
            Self::PolicyEmission => "policy-emission.lock".into(),
            Self::ControlCreate => "control-create.lock".into(),
            Self::CatalogHandles => "catalog-handles.lock".into(),
            Self::ControlHandles => "control-handles.lock".into(),
            Self::HistoryReaders => "history-readers.lock".into(),
            Self::Background => "background.lock".into(),
            Self::Supervisor => "supervisor.lock".into(),
            Self::MaintenanceJob(key) => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut name = String::from("maintenance-job-");
                for byte in key.0.bytes() {
                    name.push(HEX[usize::from(byte >> 4)] as char);
                    name.push(HEX[usize::from(byte & 15)] as char);
                }
                name.push_str(".lock");
                name
            }
        }
    }
}

/// Physical directory identity, for internal capability comparison only.
/// No path, native identifier or serialization is exposed. This is not a
/// persistent catalog incarnation or permission grant.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootIdentity(PhysicalIdentity);

impl RootIdentity {
    /// Inspect an existing directory without creating any files.
    pub fn read(root: &Path) -> PortResult<Self> {
        Ok(RootDirectory::open(root)?.identity)
    }

    /// Compare a store with a live worker capability without exporting native
    /// volume/file identifiers. Aliases of the same opened root encode equally.
    /// This value never replaces the independently held OS lock.
    pub fn binding(self) -> PhysicalRootBinding {
        PhysicalRootBinding::from_verified_identity(*self.digest().as_bytes())
    }

    /// Private selection/source identity token, using the same physical digest
    /// as binding(). Persisting this token grants no permission or lock; callers
    /// must still verify path components and identity around source capture.
    pub fn control_id(self) -> ControlId {
        ControlId::parse(&format!("root_v1_{}", self.digest().to_hex()))
            .expect("root token is a fixed prefix and 64 ASCII hex digits")
    }

    fn digest(self) -> blake3::Hash {
        let mut hash = blake3::Hasher::new();
        hash.update(b"asg-physical-root-binding-v1\0");
        hash.update(&self.0.volume.to_le_bytes());
        hash.update(&self.0.file.to_le_bytes());
        hash.finalize()
    }
}

impl fmt::Debug for RootIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootIdentity([private])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PhysicalIdentity {
    volume: u64,
    file: u128,
}

struct RootDirectory {
    file: File,
    #[cfg(windows)]
    path: PathBuf,
    identity: RootIdentity,
}

impl RootDirectory {
    fn open(root: &Path) -> PortResult<Self> {
        // Resolve aliases once, then identify the opened directory itself.
        // Windows retains a non-delete-sharing handle; Unix opens children
        // relative to this descriptor, even if the directory is renamed.
        let path = fs::canonicalize(root).map_err(lock_io("root", "resolve"))?;
        let file = platform::open_root(&path).map_err(lock_io("root", "open"))?;
        if !file
            .metadata()
            .map_err(lock_io("root", "metadata"))?
            .is_dir()
        {
            return Err(lock_invalid("root", "kind"));
        }
        let identity =
            RootIdentity(platform::identity(&file).map_err(lock_io("root", "identity"))?);
        Ok(Self {
            file,
            #[cfg(windows)]
            path,
            identity,
        })
    }

    /// `site` names the caller in diagnostics only: first acquisition, the
    /// post-lock recheck or a later currency check.
    fn open_lock(&self, kind: &LockKind, create: bool, site: &'static str) -> PortResult<File> {
        let file =
            platform::open_lock(self, &kind.filename(), create).map_err(lock_io(site, "open"))?;
        let metadata = file.metadata().map_err(lock_io(site, "metadata"))?;
        // Never truncate unexpected content or touch bytes protected by a
        // Windows mandatory byte-range lock. Hard links are rejected as aliases.
        if !metadata.is_file() {
            return Err(lock_invalid(site, "kind"));
        }
        if metadata.len() != 0 {
            return Err(lock_invalid(site, "length"));
        }
        platform::validate_lock(&file).map_err(lock_io(site, "links"))?;
        Ok(file)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Shared,
    Exclusive,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct RegistryKey {
    root: RootIdentity,
    kind: LockKind,
}

struct Holders {
    file: PhysicalIdentity,
    mode: Mode,
    count: usize,
}

fn registry() -> &'static Mutex<HashMap<RegistryKey, Holders>> {
    static REGISTRY: OnceLock<Mutex<HashMap<RegistryKey, Holders>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Reservation precedes the OS call and rolls back on every failed acquisition.
struct Claim(RegistryKey);

impl Claim {
    fn acquire(key: RegistryKey, file: PhysicalIdentity, mode: Mode) -> PortResult<Self> {
        // Wait for the in-memory critical section instead of reporting busy:
        // it holds no filesystem call or user callback, so contention for an
        // unrelated root or lock kind is never a lock conflict. Only an
        // incompatible holder of this exact key below reports busy.
        let mut held = registry()
            .lock()
            .map_err(|_| lock_invalid("claim", "registry"))?;
        if let Some(previous) = held.get_mut(&key) {
            if previous.mode != Mode::Shared || mode != Mode::Shared || previous.file != file {
                return Err(busy());
            }
            previous.count = previous.count.checked_add(1).ok_or_else(busy)?;
        } else {
            held.insert(
                key.clone(),
                Holders {
                    file,
                    mode,
                    count: 1,
                },
            );
        }
        Ok(Self(key))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        // Cleanup must not abandon a reservation on transient mutex contention.
        // No filesystem calls or user callbacks execute under this mutex.
        let mut held = registry().lock().unwrap_or_else(|error| error.into_inner());
        if let Some(previous) = held.get_mut(&self.0) {
            previous.count -= 1;
            if previous.count == 0 {
                held.remove(&self.0);
            }
        }
    }
}

struct Guard {
    root: RootDirectory,
    file: Option<File>,
    claim: Claim,
}

impl Guard {
    fn acquire(root: &Path, kind: LockKind, mode: Mode) -> PortResult<Self> {
        Self::acquire_existing_or_create(root, kind, mode, true)
    }

    fn acquire_existing_or_create(
        root: &Path,
        kind: LockKind,
        mode: Mode,
        create: bool,
    ) -> PortResult<Self> {
        let root = RootDirectory::open(root)?;
        let file = root.open_lock(&kind, create, if create { "lock" } else { "existing" })?;
        let identity = platform::identity(&file).map_err(lock_io("acquire", "identity"))?;
        let claim = Claim::acquire(
            RegistryKey {
                root: root.identity,
                kind,
            },
            identity,
            mode,
        )?;
        let result = match mode {
            Mode::Shared => FileExt::try_lock_shared(&file),
            Mode::Exclusive => FileExt::try_lock_exclusive(&file),
        };
        classify_lock_result(result)?;
        let guard = Self {
            root,
            file: Some(file),
            claim,
        };
        // Detect replacement during acquisition without reading lock-file data.
        // A later noncooperating unlink on Unix is outside advisory lock safety;
        // all ASG cleanup/update paths must retain these persistent inodes.
        let named = guard
            .root
            .open_lock(&guard.claim.0.kind, false, "recheck")?;
        if platform::identity(&named).map_err(lock_io("recheck", "identity"))? != identity {
            return Err(lock_invalid("recheck", "replaced"));
        }
        Ok(guard)
    }

    fn acquire_existing(root: &Path, kind: LockKind, mode: Mode) -> PortResult<Option<Self>> {
        let directory = RootDirectory::open(root)?;
        if !platform::child_exists(&directory, &kind.filename())
            .map_err(lock_io("existing", "probe"))?
        {
            return Ok(None);
        }
        Self::acquire_existing_or_create(root, kind, mode, false).map(Some)
    }
}

impl Guard {
    fn validate_current(&self, path: &Path) -> PortResult<()> {
        if RootIdentity::read(path)? != self.root.identity {
            return Err(lock_invalid("current", "root"));
        }
        let held = self
            .file
            .as_ref()
            .ok_or_else(|| lock_invalid("current", "released"))?;
        let named = self.root.open_lock(&self.claim.0.kind, false, "current")?;
        if platform::identity(held).map_err(lock_io("current", "held_identity"))?
            != platform::identity(&named).map_err(lock_io("current", "named_identity"))?
        {
            return Err(lock_invalid("current", "replaced"));
        }
        Ok(())
    }

    fn child_exists(&self, name: &str) -> PortResult<bool> {
        validate_child_name(name)?;
        platform::child_exists(&self.root, name).map_err(lock_io("child", "probe"))
    }

    fn open_child_read(&self, name: &str) -> PortResult<File> {
        validate_child_name(name)?;
        let file = platform::open_child_read(&self.root, name).map_err(lock_io("child", "open"))?;
        self.validate_child(name, &file)?;
        Ok(file)
    }

    fn validate_child(&self, name: &str, file: &File) -> PortResult<()> {
        validate_child_name(name)?;
        if !file
            .metadata()
            .map_err(lock_io("child", "metadata"))?
            .is_file()
        {
            return Err(lock_invalid("child", "kind"));
        }
        platform::validate_lock(file).map_err(lock_io("child", "links"))?;
        let named =
            platform::open_child_read(&self.root, name).map_err(lock_io("child", "reopen"))?;
        platform::validate_lock(&named).map_err(lock_io("child", "reopen_links"))?;
        if platform::identity(file).map_err(lock_io("child", "identity"))?
            != platform::identity(&named).map_err(lock_io("child", "reopen_identity"))?
        {
            return Err(lock_invalid("child", "replaced"));
        }
        Ok(())
    }

    fn create_child_new(&self, name: &str) -> PortResult<File> {
        validate_child_name(name)?;
        platform::create_child_new(&self.root, name).map_err(lock_io("child", "create"))
    }

    fn remove_child(&self, name: &str) -> PortResult<bool> {
        validate_child_name(name)?;
        platform::remove_child(&self.root, name).map_err(lock_io("child", "remove"))
    }

    fn sync_child(&self, name: &str) -> PortResult<()> {
        validate_child_name(name)?;
        let file =
            platform::open_lock(&self.root, name, false).map_err(lock_io("child", "sync_open"))?;
        if !file
            .metadata()
            .map_err(lock_io("child", "sync_metadata"))?
            .is_file()
        {
            return Err(lock_invalid("child", "sync_kind"));
        }
        platform::validate_lock(&file).map_err(lock_io("child", "sync_links"))?;
        file.sync_all().map_err(lock_io("child", "sync"))
    }

    fn publish_child_no_replace(&self, pending: &str, final_name: &str) -> PortResult<()> {
        validate_child_name(pending)?;
        validate_child_name(final_name)?;
        platform::publish_child_no_replace(&self.root, pending, final_name)
            .map_err(lock_io("child", "publish"))
    }

    fn sync_directory(&self) -> PortResult<()> {
        platform::sync_directory(&self.root).map_err(lock_io("root", "sync"))
    }
}

fn validate_child_name(name: &str) -> PortResult<()> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(lock_invalid("child", "name"));
    }
    Ok(())
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = FileExt::unlock(&file);
            // Closing the independently owned handle also releases the lock if
            // explicit unlock failed, before Claim unregisters this holder.
            drop(file);
        }
    }
}

/// Non-cloneable capability for one frame or one database-connection lifetime.
#[must_use = "dropping the guard releases the managed lock"]
pub struct SharedGuard(Guard);

impl SharedGuard {
    /// Nonblocking. PolicyEmission, CatalogHandles and ControlHandles share.
    /// A missing root is an error; an absent lock file in an existing root is
    /// created empty. No catalog, control database or directory is created.
    pub fn try_acquire(root: &Path, kind: LockKind) -> PortResult<Self> {
        if !matches!(
            kind,
            LockKind::PolicyEmission
                | LockKind::CatalogHandles
                | LockKind::ControlHandles
                | LockKind::HistoryReaders
        ) {
            return Err(invalid());
        }
        Guard::acquire(root, kind, Mode::Shared).map(Self)
    }

    pub fn root_identity(&self) -> RootIdentity {
        self.0.root.identity
    }

    pub fn kind(&self) -> &LockKind {
        &self.0.claim.0.kind
    }

    /// Recheck the actual root and persistent lock inode; never acquires anew.
    pub(crate) fn validate_current(&self, root: &Path) -> PortResult<()> {
        self.0.validate_current(root)
    }

    pub(crate) fn child_exists(&self, name: &str) -> PortResult<bool> {
        self.0.child_exists(name)
    }

    pub(crate) fn open_child_read(&self, name: &str) -> PortResult<File> {
        self.0.open_child_read(name)
    }

    pub(crate) fn validate_child(&self, name: &str, file: &File) -> PortResult<()> {
        self.0.validate_child(name, file)
    }

    pub(crate) fn publish_child_no_replace(
        &self,
        pending: &str,
        final_name: &str,
    ) -> PortResult<()> {
        self.0.publish_child_no_replace(pending, final_name)
    }
}

/// Non-cloneable capability proving exclusive ownership while held.
#[must_use = "dropping the guard releases the managed lock"]
pub struct ExclusiveGuard(Guard);

impl ExclusiveGuard {
    /// Nonblocking; contention is a bounded, path-redacted WriterBusy error.
    /// Callers retain this capability until protected work is complete.
    pub fn try_acquire(root: &Path, kind: LockKind) -> PortResult<Self> {
        Guard::acquire(root, kind, Mode::Exclusive).map(Self)
    }

    /// Read-only admission may reuse an existing create rendezvous without
    /// creating one. A missing rendezvous means no durable creation began.
    pub(crate) fn try_acquire_existing(root: &Path, kind: LockKind) -> PortResult<Option<Self>> {
        if !matches!(kind, LockKind::ControlCreate) {
            return Err(invalid());
        }
        Guard::acquire_existing(root, kind, Mode::Exclusive).map(|guard| guard.map(Self))
    }

    pub fn root_identity(&self) -> RootIdentity {
        self.0.root.identity
    }

    pub fn kind(&self) -> &LockKind {
        &self.0.claim.0.kind
    }

    /// Recheck the actual root and persistent lock inode; never acquires anew.
    pub(crate) fn validate_current(&self, root: &Path) -> PortResult<()> {
        self.0.validate_current(root)
    }

    pub(crate) fn child_exists(&self, name: &str) -> PortResult<bool> {
        self.0.child_exists(name)
    }

    pub(crate) fn open_child_read(&self, name: &str) -> PortResult<File> {
        self.0.open_child_read(name)
    }

    pub(crate) fn validate_child(&self, name: &str, file: &File) -> PortResult<()> {
        self.0.validate_child(name, file)
    }

    pub(crate) fn create_child_new(&self, name: &str) -> PortResult<File> {
        self.0.create_child_new(name)
    }

    pub(crate) fn remove_child(&self, name: &str) -> PortResult<bool> {
        self.0.remove_child(name)
    }

    pub(crate) fn sync_child(&self, name: &str) -> PortResult<()> {
        self.0.sync_child(name)
    }

    pub(crate) fn publish_child_no_replace(
        &self,
        pending: &str,
        final_name: &str,
    ) -> PortResult<()> {
        self.0.publish_child_no_replace(pending, final_name)
    }

    pub(crate) fn sync_directory(&self) -> PortResult<()> {
        self.0.sync_directory()
    }
}

impl fmt::Debug for SharedGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedGuard")
            .field("kind", self.kind())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ExclusiveGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExclusiveGuard")
            .field("kind", self.kind())
            .finish_non_exhaustive()
    }
}

fn busy() -> PortError {
    PortError::WriterBusy("managed lock is busy".into())
}

fn invalid() -> PortError {
    PortError::SourceIo("managed lock storage or request is invalid".into())
}

/// Fixed diagnosis for one refused lock step: a static call site and step,
/// never a path, file name, native identifier or OS message.
fn lock_invalid(site: &'static str, step: &'static str) -> PortError {
    PortError::SourceIo(format!(
        "managed lock storage or request is invalid (site={site}, step={step})"
    ))
}

/// Like `io_error`, plus the static site/step and the numeric OS cause (zero
/// when absent). Busy classification is unchanged.
fn lock_io(site: &'static str, step: &'static str) -> impl Fn(io::Error) -> PortError {
    move |error| {
        let code = error.raw_os_error().unwrap_or(0);
        match io_error(error) {
            PortError::SourceIo(_) => PortError::SourceIo(format!(
                "managed lock storage is unavailable (site={site}, step={step}, code={code})"
            )),
            busy => busy,
        }
    }
}

fn io_error(error: io::Error) -> PortError {
    #[cfg(windows)]
    if matches!(error.raw_os_error(), Some(32 | 33)) {
        return busy();
    }
    if error.kind() == io::ErrorKind::WouldBlock {
        busy()
    } else {
        PortError::SourceIo("managed lock storage is unavailable".into())
    }
}

fn classify_lock_result(result: io::Result<bool>) -> PortResult<()> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(busy()),
        Err(error) => Err(lock_io("acquire", "try_lock")(error)),
    }
}

#[cfg(windows)]
pub(crate) mod platform {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
        FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
    };

    fn reject() -> io::Error {
        io::Error::from(io::ErrorKind::InvalidInput)
    }

    pub(super) fn open_root(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(reject());
        }
        Ok(file)
    }

    pub(super) fn open_lock(root: &RootDirectory, name: &str, create: bool) -> io::Result<File> {
        let path = root.path.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if !metadata.is_file()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 =>
            {
                return Err(reject());
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        // Share READ and WRITE so another independently opened handle can
        // reach LockFileEx. Denying DELETE prevents replacement while held.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if identity(&open_root(&root.path)?)? != identity(&root.file)? {
            return Err(reject());
        }
        Ok(file)
    }

    pub(super) fn child_exists(root: &RootDirectory, name: &str) -> io::Result<bool> {
        if identity(&open_root(&root.path)?)? != identity(&root.file)? {
            return Err(reject());
        }
        match fs::symlink_metadata(root.path.join(name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn open_child_read(root: &RootDirectory, name: &str) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root.path.join(name))?;
        if identity(&open_root(&root.path)?)? != identity(&root.file)?
            || !file.metadata()?.is_file()
        {
            return Err(reject());
        }
        validate_lock(&file)?;
        Ok(file)
    }

    pub(super) fn create_child_new(root: &RootDirectory, name: &str) -> io::Result<File> {
        if identity(&open_root(&root.path)?)? != identity(&root.file)? {
            return Err(reject());
        }
        crate::control::create_private_owned_file(&root.path.join(name))
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))
    }

    pub(super) fn publish_child_no_replace(
        root: &RootDirectory,
        pending: &str,
        final_name: &str,
    ) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
        if identity(&open_root(&root.path)?)? != identity(&root.file)? {
            return Err(reject());
        }
        let source: Vec<u16> = root
            .path
            .join(pending)
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let destination: Vec<u16> = root
            .path
            .join(final_name)
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: both terminated paths live through this no-replacement move;
        // the pinned root denies deletion and WRITE_THROUGH requests durability.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        publication_sync_boundary()
    }

    pub(super) fn remove_child(root: &RootDirectory, name: &str) -> io::Result<bool> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };
        if identity(&open_root(&root.path)?)? != identity(&root.file)? {
            return Err(reject());
        }
        let path = root.path.join(name);
        // Delete the exact no-follow leaf handle, never a later path alias.
        let file = match OpenOptions::new()
            .access_mode(0x10000 | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(reject());
        }
        validate_lock(&file)?;
        crate::control::validate_private_owned_file(&path)
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let mut disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: exact matching class/structure and live owned leaf handle.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&mut disposition as *mut FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(file);
        Ok(true)
    }

    pub(super) fn sync_directory(_: &RootDirectory) -> io::Result<()> {
        // Windows publication uses MoveFileExW(MOVEFILE_WRITE_THROUGH) after
        // flushing the file; a read-only directory handle cannot be flushed.
        Ok(())
    }

    pub(super) fn identity(file: &File) -> io::Result<PhysicalIdentity> {
        let mut info = FILE_ID_INFO::default();
        // SAFETY: the live owned handle and writable FILE_ID_INFO buffer remain
        // valid throughout the call; its exact size is supplied, no pointer escapes.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PhysicalIdentity {
            volume: info.VolumeSerialNumber,
            file: u128::from_le_bytes(info.FileId.Identifier),
        })
    }

    pub(super) fn validate_lock(file: &File) -> io::Result<()> {
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(reject());
        }
        let mut info = FILE_STANDARD_INFO::default();
        // SAFETY: as above, using the matching FILE_STANDARD_INFO buffer/class.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStandardInfo,
                (&mut info as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.NumberOfLinks != 1 {
            return Err(reject());
        }
        Ok(())
    }
}

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
pub(crate) mod platform {
    use super::*;
    use std::{
        ffi::CString,
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
    };

    // Native open(2) flags for the supported Unix package targets. No libc
    // dependency is added solely for opening relative to a pinned directory.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const FLAGS: (i32, i32, i32, i32, i32) = (0x20000, 0x80000, 0x800, 0x10000, 0x40);
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const FLAGS: (i32, i32, i32, i32, i32) = (0x8000, 0x80000, 0x800, 0x4000, 0x40);
    #[cfg(target_os = "macos")]
    const FLAGS: (i32, i32, i32, i32, i32) = (0x100, 0x1000000, 0x4, 0x100000, 0x200);
    pub(crate) const NOFOLLOW: i32 = FLAGS.0;
    pub(crate) const CLOEXEC: i32 = FLAGS.1;
    pub(crate) const NONBLOCK: i32 = FLAGS.2;
    pub(crate) const DIRECTORY: i32 = FLAGS.3;
    pub(crate) const CREATE: i32 = FLAGS.4;

    unsafe extern "C" {
        fn openat(directory: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    }

    pub(super) fn open_root(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(DIRECTORY | NOFOLLOW | NONBLOCK)
            .open(path)
    }

    pub(super) fn open_lock(root: &RootDirectory, name: &str, create: bool) -> io::Result<File> {
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let flags = 2 | NOFOLLOW | CLOEXEC | NONBLOCK | if create { CREATE } else { 0 };
        // SAFETY: root owns the live directory descriptor; name is NUL terminated,
        // and mode is supplied for O_CREAT. A successful fresh fd is owned once.
        let fd = unsafe { openat(root.file.as_raw_fd(), name.as_ptr(), flags, 0o600_u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh owned descriptor, transferred to File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn child_exists(root: &RootDirectory, name: &str) -> io::Result<bool> {
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // A no-follow open can reject a symlink/FIFO as invalid: that is still
        // an existing retirement marker and normal admission must fail closed.
        // SAFETY: the pinned directory fd and terminated name live through openat.
        let fd = unsafe {
            openat(
                root.file.as_raw_fd(),
                name.as_ptr(),
                NOFOLLOW | CLOEXEC | NONBLOCK,
                0o600_u32,
            )
        };
        if fd >= 0 {
            // SAFETY: openat returned one fresh owned fd.
            drop(unsafe { File::from_raw_fd(fd) });
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else if (cfg!(target_os = "linux") && error.raw_os_error() == Some(40))
            || (cfg!(target_os = "macos") && error.raw_os_error() == Some(62))
        {
            Ok(true)
        } else {
            Err(error)
        }
    }

    pub(super) fn open_child_read(root: &RootDirectory, name: &str) -> io::Result<File> {
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: descriptor/name are pinned; successful fd transfers once.
        let fd = unsafe {
            openat(
                root.file.as_raw_fd(),
                name.as_ptr(),
                NOFOLLOW | CLOEXEC | NONBLOCK,
                0o600_u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh owned fd from openat.
        let file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        validate_lock(&file)?;
        Ok(file)
    }

    pub(super) fn create_child_new(root: &RootDirectory, name: &str) -> io::Result<File> {
        #[cfg(target_os = "linux")]
        const EXCLUSIVE: i32 = 0x80;
        #[cfg(target_os = "macos")]
        const EXCLUSIVE: i32 = 0x800;
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: creates one owned 0600 regular file relative to the pinned
        // directory; O_EXCL/NOFOLLOW never overwrites or follows an existing file.
        let fd = unsafe {
            openat(
                root.file.as_raw_fd(),
                name.as_ptr(),
                1 | CREATE | EXCLUSIVE | NOFOLLOW | CLOEXEC | NONBLOCK,
                0o600_u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh owned fd returned by openat.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn publish_child_no_replace(
        root: &RootDirectory,
        pending: &str,
        final_name: &str,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        unsafe extern "C" {
            fn renameat2(
                old_dir: i32,
                old_path: *const std::ffi::c_char,
                new_dir: i32,
                new_path: *const std::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        #[cfg(target_os = "macos")]
        unsafe extern "C" {
            fn renameatx_np(
                old_dir: i32,
                old_path: *const std::ffi::c_char,
                new_dir: i32,
                new_path: *const std::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        let pending =
            CString::new(pending).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let final_name =
            CString::new(final_name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let directory = root.file.as_raw_fd();
        #[cfg(target_os = "linux")]
        // SAFETY: terminated sibling names and the pinned fd live through the
        // call. RENAME_NOREPLACE refuses a competing marker atomically.
        let result = unsafe {
            renameat2(
                directory,
                pending.as_ptr(),
                directory,
                final_name.as_ptr(),
                1,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: same as above; RENAME_EXCL is the native macOS no-replace flag.
        let result = unsafe {
            renameatx_np(
                directory,
                pending.as_ptr(),
                directory,
                final_name.as_ptr(),
                4,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        publication_sync_boundary()?;
        root.file.sync_all()
    }

    pub(super) fn remove_child(root: &RootDirectory, name: &str) -> io::Result<bool> {
        unsafe extern "C" {
            fn unlinkat(directory: i32, path: *const std::ffi::c_char, flags: i32) -> i32;
        }
        let pinned = match open_child_read(root, name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let named = open_child_read(root, name)?;
        if identity(&pinned)? != identity(&named)? {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: only this validated owned leaf relative to the pinned directory
        // is unlinked while all cooperating lifecycle domains remain exclusive.
        if unsafe { unlinkat(root.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        root.file.sync_all()?;
        Ok(true)
    }

    pub(super) fn sync_directory(root: &RootDirectory) -> io::Result<()> {
        root.file.sync_all()
    }

    pub(super) fn identity(file: &File) -> io::Result<PhysicalIdentity> {
        let metadata = file.metadata()?;
        Ok(PhysicalIdentity {
            volume: metadata.dev(),
            file: u128::from(metadata.ino()),
        })
    }

    pub(super) fn validate_lock(file: &File) -> io::Result<()> {
        if file.metadata()?.nlink() != 1 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(())
    }
}

#[cfg(not(any(
    windows,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
)))]
mod platform {
    use super::*;
    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    pub(super) fn open_root(_: &Path) -> io::Result<File> {
        unsupported()
    }
    pub(super) fn open_lock(_: &RootDirectory, _: &str, _: bool) -> io::Result<File> {
        unsupported()
    }
    pub(super) fn child_exists(_: &RootDirectory, _: &str) -> io::Result<bool> {
        unsupported()
    }
    pub(super) fn open_child_read(_: &RootDirectory, _: &str) -> io::Result<File> {
        unsupported()
    }
    pub(super) fn create_child_new(_: &RootDirectory, _: &str) -> io::Result<File> {
        unsupported()
    }
    pub(super) fn publish_child_no_replace(_: &RootDirectory, _: &str, _: &str) -> io::Result<()> {
        unsupported()
    }
    pub(super) fn remove_child(_: &RootDirectory, _: &str) -> io::Result<bool> {
        unsupported()
    }
    pub(super) fn sync_directory(_: &RootDirectory) -> io::Result<()> {
        unsupported()
    }
    pub(super) fn identity(_: &File) -> io::Result<PhysicalIdentity> {
        unsupported()
    }
    pub(super) fn validate_lock(_: &File) -> io::Result<()> {
        unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Child, Command, Stdio},
    };

    // Synthetic empty roots only; no provider histories or host configuration.
    fn assert_busy<T: fmt::Debug>(result: PortResult<T>) {
        assert!(
            matches!(result, Err(PortError::WriterBusy(_))),
            "{result:?}"
        );
    }

    // Bypass the process registry so it cannot hide an OS lock whose lifetime
    // accidentally ended when a different independently opened handle closed.
    fn assert_os_exclusive_busy(root: &Path, kind: &LockKind) {
        let directory = RootDirectory::open(root).unwrap();
        let contender = directory.open_lock(kind, false, "test").unwrap();
        assert_busy(classify_lock_result(FileExt::try_lock_exclusive(
            &contender,
        )));
    }

    // A try call may meet another thread's brief reservation of the same key.
    // This is the caller-owned bounded retry contract, not an ownership timeout.
    fn acquire<T>(mut attempt: impl FnMut() -> PortResult<T>) -> T {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match attempt() {
                Ok(guard) => return guard,
                Err(PortError::WriterBusy(_)) if std::time::Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("lock acquisition failed: {error:?}"),
            }
        }
    }

    #[test]
    fn shared_holders_release_independently() {
        for kind in [
            LockKind::PolicyEmission,
            LockKind::CatalogHandles,
            LockKind::ControlHandles,
            LockKind::HistoryReaders,
        ] {
            let root = agent_session_grep_testkit::tempdir().unwrap();
            let first = acquire(|| SharedGuard::try_acquire(root.path(), kind.clone()));
            let second = acquire(|| SharedGuard::try_acquire(root.path(), kind.clone()));
            assert_eq!(
                first.root_identity(),
                RootIdentity::read(root.path()).unwrap()
            );
            assert_busy(ExclusiveGuard::try_acquire(root.path(), kind.clone()));
            assert_os_exclusive_busy(root.path(), &kind);
            drop(first);
            assert_busy(ExclusiveGuard::try_acquire(root.path(), kind.clone()));
            assert_os_exclusive_busy(root.path(), &kind);
            drop(second);
            let exclusive = acquire(|| ExclusiveGuard::try_acquire(root.path(), kind.clone()));
            assert_busy(SharedGuard::try_acquire(root.path(), kind.clone()));
            assert_busy(ExclusiveGuard::try_acquire(root.path(), kind.clone()));
            drop(exclusive);
            drop(acquire(|| {
                SharedGuard::try_acquire(root.path(), kind.clone())
            }));
            assert_eq!(
                fs::metadata(root.path().join(kind.filename()))
                    .unwrap()
                    .len(),
                0
            );
        }
    }

    #[test]
    fn control_root_token_uses_physical_identity_without_raw_identifiers() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let other = agent_session_grep_testkit::tempdir().unwrap();
        let first = RootIdentity::read(root.path()).unwrap();
        let reopened = RootIdentity::read(&root.path().canonicalize().unwrap()).unwrap();
        let distinct = RootIdentity::read(other.path()).unwrap();
        assert_eq!(first.binding(), reopened.binding());
        assert_eq!(first.control_id(), reopened.control_id());
        assert_ne!(first.binding(), distinct.binding());
        assert_ne!(first.control_id(), distinct.control_id());
        let token = first.control_id();
        assert_eq!(ControlId::parse(token.as_str()).unwrap(), token);
        assert_eq!(token.as_str().len(), "root_v1_".len() + 64);
        assert!(!format!("{token:?}").contains(token.as_str()));
        assert!(!token.as_str().contains(&root.path().display().to_string()));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn kinds_roots_and_job_case_are_independent() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let other = agent_session_grep_testkit::tempdir().unwrap();
        let kinds = [
            LockKind::PolicyOwner,
            LockKind::PolicyEmission,
            LockKind::ControlCreate,
            LockKind::CatalogHandles,
            LockKind::ControlHandles,
            LockKind::HistoryReaders,
            LockKind::Background,
            LockKind::Supervisor,
            LockKind::MaintenanceJob(JobLockKey::parse("job-A").unwrap()),
            LockKind::MaintenanceJob(JobLockKey::parse("job-a").unwrap()),
        ];
        let guards: Vec<_> = kinds
            .iter()
            .map(|kind| acquire(|| ExclusiveGuard::try_acquire(root.path(), kind.clone())))
            .collect();
        for (kind, guard) in kinds.iter().zip(&guards) {
            assert_eq!(guard.kind(), kind);
            assert_busy(ExclusiveGuard::try_acquire(root.path(), kind.clone()));
            drop(acquire(|| {
                ExclusiveGuard::try_acquire(other.path(), kind.clone())
            }));
        }
    }

    #[test]
    fn invalid_inputs_have_no_root_or_catalog_side_effects() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert!(ExclusiveGuard::try_acquire(&missing, LockKind::PolicyOwner).is_err());
        assert!(!missing.exists());
        assert!(RootIdentity::read(&missing).is_err());
        assert!(SharedGuard::try_acquire(root.path(), LockKind::Background).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        for value in ["", "../job", "a/b", "a:b", "a\\b", "..", &"x".repeat(65)] {
            assert!(JobLockKey::parse(value).is_err());
        }
        let lock = root.path().join(LockKind::PolicyOwner.filename());
        fs::create_dir(&lock).unwrap();
        assert!(ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyOwner).is_err());
        fs::remove_dir(&lock).unwrap();
        fs::write(&lock, b"synthetic unexpected content").unwrap();
        assert!(ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyOwner).is_err());
        assert_eq!(fs::read(&lock).unwrap(), b"synthetic unexpected content");
        assert!(RootIdentity::read(&lock).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn hard_link_lock_alias_is_rejected_without_modifying_it() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let target = root.path().join("synthetic-target");
        fs::write(&target, []).unwrap();
        let lock = root.path().join(LockKind::PolicyOwner.filename());
        fs::hard_link(&target, &lock).unwrap();
        assert!(ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyOwner).is_err());
        assert!(target.exists() && lock.exists());
        assert_eq!(fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn failures_roll_back_claim_and_redact_details() {
        assert_busy(classify_lock_result(Ok(false)));
        assert_busy(classify_lock_result(Err(io::ErrorKind::WouldBlock.into())));
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let guard = acquire(|| ExclusiveGuard::try_acquire(root.path(), LockKind::Background));
        let error = ExclusiveGuard::try_acquire(root.path(), LockKind::Background).unwrap_err();
        for text in [
            format!("{error}"),
            format!("{error:?}"),
            format!("{guard:?}"),
            format!("{:?}", guard.root_identity()),
            format!("{:?}", JobLockKey::parse("private-job").unwrap()),
            format!(
                "{:?}",
                io_error(io::Error::other(root.path().display().to_string()))
            ),
        ] {
            assert!(!text.contains(&root.path().display().to_string()));
            assert!(!text.contains("private-job"));
            assert!(!text.contains("background.lock"));
            assert!(text.len() < 160);
        }
        drop(guard);
        drop(acquire(|| {
            ExclusiveGuard::try_acquire(root.path(), LockKind::Background)
        }));
    }

    #[test]
    fn concurrent_exclusive_requests_have_one_owner() {
        use std::sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
        };
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let start = Arc::new(Barrier::new(8));
        let acquired = Arc::new(Barrier::new(8));
        let winner = AtomicBool::new(false);
        let winners = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    let (start, acquired) = (start.clone(), acquired.clone());
                    let path = root.path();
                    let winner = &winner;
                    scope.spawn(move || {
                        start.wait();
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(5);
                        let guard = loop {
                            match ExclusiveGuard::try_acquire(path, LockKind::Background) {
                                Ok(guard) => {
                                    assert!(!winner.swap(true, Ordering::SeqCst));
                                    break Some(guard);
                                }
                                Err(PortError::WriterBusy(_)) if winner.load(Ordering::SeqCst) => {
                                    break None;
                                }
                                Err(PortError::WriterBusy(_))
                                    if std::time::Instant::now() < deadline =>
                                {
                                    std::thread::yield_now()
                                }
                                Err(error) => panic!("{error:?}"),
                            }
                        };
                        acquired.wait();
                        usize::from(guard.is_some())
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .sum::<usize>()
        });
        assert_eq!(winners, 1);
        drop(acquire(|| {
            ExclusiveGuard::try_acquire(root.path(), LockKind::Background)
        }));
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_alias_and_delete_sharing() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let holder = acquire(|| ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyOwner));
        let alias = PathBuf::from(root.path().as_os_str().to_string_lossy().to_uppercase());
        assert_eq!(holder.root_identity(), RootIdentity::read(&alias).unwrap());
        assert_eq!(
            holder.root_identity().control_id(),
            RootIdentity::read(&alias).unwrap().control_id()
        );
        assert_busy(ExclusiveGuard::try_acquire(&alias, LockKind::PolicyOwner));
        let long: Vec<u16> = root
            .path()
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut short = vec![0_u16; long.len() + 1];
        // SAFETY: both UTF-16 buffers are live, long is terminated and short's
        // allocated capacity is supplied. No returned pointer is retained.
        let len =
            unsafe { GetShortPathNameW(long.as_ptr(), short.as_mut_ptr(), short.len() as u32) }
                as usize;
        assert!(len > 0 && len < short.len());
        let short = PathBuf::from(std::ffi::OsString::from_wide(&short[..len]));
        assert_eq!(holder.root_identity(), RootIdentity::read(&short).unwrap());
        assert_eq!(
            holder.root_identity().control_id(),
            RootIdentity::read(&short).unwrap().control_id()
        );
        assert_busy(ExclusiveGuard::try_acquire(&short, LockKind::PolicyOwner));
        assert!(fs::remove_file(root.path().join(LockKind::PolicyOwner.filename())).is_err());
        for code in [32, 33] {
            assert_busy(classify_lock_result(Err(io::Error::from_raw_os_error(
                code,
            ))));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_junction_alias_and_final_reparse_rejection() {
        let parent = agent_session_grep_testkit::tempdir().unwrap();
        let root = parent.path().join("root");
        fs::create_dir(&root).unwrap();
        let alias = parent.path().join("alias");
        let lock_alias = root.join(LockKind::Background.filename());
        // Junction creation does not require symlink privilege or change any
        // machine setting. Arguments are passed via child-only env, not code.
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:ASG_TEST_ALIAS -Target $env:ASG_TEST_TARGET | Out-Null; New-Item -ItemType Junction -Path $env:ASG_TEST_LOCK_ALIAS -Target $env:ASG_TEST_TARGET | Out-Null"])
            .env("ASG_TEST_ALIAS", &alias).env("ASG_TEST_TARGET", &root)
            .env("ASG_TEST_LOCK_ALIAS", &lock_alias).output().unwrap();
        assert!(output.status.success(), "junction fixture creation failed");
        let holder = acquire(|| ExclusiveGuard::try_acquire(&root, LockKind::PolicyOwner));
        assert_eq!(holder.root_identity(), RootIdentity::read(&alias).unwrap());
        assert_eq!(
            holder.root_identity().control_id(),
            RootIdentity::read(&alias).unwrap().control_id()
        );
        assert_busy(ExclusiveGuard::try_acquire(&alias, LockKind::PolicyOwner));
        assert!(ExclusiveGuard::try_acquire(&root, LockKind::Background).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires Windows Developer Mode or symlink privilege; run explicitly on a capable host"]
    fn windows_final_file_symlink_never_creates_target() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let target = root.path().join("missing-target");
        let link = root.path().join(LockKind::PolicyOwner.filename());
        // Junction/reparse rejection runs in the ordinary suite. This additional
        // file-symlink case explicitly fails if the required privilege is absent.
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        assert!(ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyOwner).is_err());
        assert!(!target.exists());
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_symlink_root_alias_and_final_lock_rejection() {
        use std::os::unix::fs::symlink;
        let parent = agent_session_grep_testkit::tempdir().unwrap();
        let root = parent.path().join("root");
        fs::create_dir(&root).unwrap();
        let alias = parent.path().join("alias");
        symlink(&root, &alias).unwrap();
        let holder = acquire(|| ExclusiveGuard::try_acquire(&root, LockKind::PolicyOwner));
        assert_eq!(holder.root_identity(), RootIdentity::read(&alias).unwrap());
        assert_eq!(
            holder.root_identity().control_id(),
            RootIdentity::read(&alias).unwrap().control_id()
        );
        assert_busy(ExclusiveGuard::try_acquire(&alias, LockKind::PolicyOwner));
        let target = parent.path().join("missing-target");
        symlink(&target, root.join(LockKind::Background.filename())).unwrap();
        assert!(ExclusiveGuard::try_acquire(&root, LockKind::Background).is_err());
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_directory_descriptor_survives_root_rename() {
        let parent = agent_session_grep_testkit::tempdir().unwrap();
        let root = parent.path().join("root");
        let moved = parent.path().join("moved");
        fs::create_dir(&root).unwrap();
        let pinned = RootDirectory::open(&root).unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        let file = pinned
            .open_lock(&LockKind::PolicyOwner, true, "test")
            .unwrap();
        assert_eq!(
            pinned.identity.control_id(),
            RootIdentity::read(&moved).unwrap().control_id()
        );
        assert_ne!(
            pinned.identity.control_id(),
            RootIdentity::read(&root).unwrap().control_id()
        );
        assert_eq!(file.metadata().unwrap().len(), 0);
        assert!(moved.join(LockKind::PolicyOwner.filename()).is_file());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    // The test binary itself is the cooperating process. Pipe handshakes define
    // lock ordering; no sleeps or PID/elapsed-time ownership guesses are used.
    const CHILD_ENV: &str = "ASG_MANAGED_LOCK_TEST_CHILD";
    const ROOT_ENV: &str = "ASG_MANAGED_LOCK_TEST_ROOT";

    #[test]
    fn managed_lock_child() {
        let Ok(mode) = std::env::var(CHILD_ENV) else {
            return;
        };
        let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
        let shared = if mode == "shared" {
            Some(acquire(|| {
                SharedGuard::try_acquire(&root, LockKind::PolicyEmission)
            }))
        } else {
            None
        };
        let exclusive = if mode == "exclusive" {
            Some(acquire(|| {
                ExclusiveGuard::try_acquire(&root, LockKind::PolicyEmission)
            }))
        } else {
            None
        };
        println!("managed-lock-ready");
        io::stdout().flush().unwrap();
        let mut command = String::new();
        io::stdin().read_line(&mut command).unwrap();
        if command.trim() == "crash" {
            std::process::exit(23);
        }
        drop(shared);
        drop(exclusive);
    }

    struct ChildHolder {
        child: Child,
        output: Option<BufReader<std::process::ChildStdout>>,
    }
    impl ChildHolder {
        fn start(root: &Path, mode: &str) -> Self {
            let test_name = format!(
                "{}::managed_lock_child",
                module_path!().split_once("::").unwrap().1
            );
            let mut child = Self {
                child: Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &test_name, "--nocapture"])
                    .env(CHILD_ENV, mode)
                    .env(ROOT_ENV, root)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
                output: None,
            };
            let mut output = BufReader::new(child.child.stdout.take().unwrap());
            loop {
                let mut line = String::new();
                assert_ne!(
                    output.read_line(&mut line).unwrap(),
                    0,
                    "child exited before acquiring lock"
                );
                if line.trim() == "managed-lock-ready" {
                    break;
                }
            }
            child.output = Some(output);
            child
        }

        fn finish(mut self, command: &str, code: i32) {
            writeln!(self.child.stdin.take().unwrap(), "{command}").unwrap();
            io::copy(self.output.as_mut().unwrap(), &mut io::sink()).unwrap();
            assert_eq!(self.child.wait().unwrap().code(), Some(code));
        }
    }
    impl Drop for ChildHolder {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn competing_process_shared_exclusive_and_crash_release() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let child = ChildHolder::start(root.path(), "shared");
        let local = acquire(|| SharedGuard::try_acquire(root.path(), LockKind::PolicyEmission));
        assert_busy(ExclusiveGuard::try_acquire(
            root.path(),
            LockKind::PolicyEmission,
        ));
        child.finish("release", 0);
        assert_busy(ExclusiveGuard::try_acquire(
            root.path(),
            LockKind::PolicyEmission,
        ));
        drop(local);
        let child = ChildHolder::start(root.path(), "exclusive");
        assert_busy(SharedGuard::try_acquire(
            root.path(),
            LockKind::PolicyEmission,
        ));
        assert_busy(ExclusiveGuard::try_acquire(
            root.path(),
            LockKind::PolicyEmission,
        ));
        child.finish("crash", 23);
        drop(acquire(|| {
            ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyEmission)
        }));
        let mut child = ChildHolder::start(root.path(), "shared");
        assert_busy(ExclusiveGuard::try_acquire(
            root.path(),
            LockKind::PolicyEmission,
        ));
        child.child.kill().unwrap();
        assert!(!child.child.wait().unwrap().success());
        drop(acquire(|| {
            ExclusiveGuard::try_acquire(root.path(), LockKind::PolicyEmission)
        }));
    }
}
