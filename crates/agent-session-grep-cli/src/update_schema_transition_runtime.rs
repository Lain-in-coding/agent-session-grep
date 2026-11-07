//! Native initialization and publication of a guarded transition journal.
//!
//! This layer owns record I/O, not package, SQL or process authority. In
//! particular it cannot admit a package, channel or database. The initializer
//! publishes only fixed native records under actual retained locks. The
//! automatic executor must first admit its actual image/channel and
//! retain the complete exclusion group; the unbound CLI entry still refuses.
//! Every operation uses the supplied original end, including reconciliation.

use super::{
    AdmissionV2, InternalAction, Invocation, MAX_RECORD_BYTES, OldJournalLayout, OldTerminalInput,
    SupersedeGuardV2, sha256,
    state::{ProofRecord, RecordSet, RecordSlot, StateV2, SuccessorEvidence},
};
use crate::{native_autostart::platform, package_installation::ordinary};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, RootIdentity},
};
use serde::Deserialize;
use std::{
    cell::Cell,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const ACTIVE: &str = "state.json";
const CANDIDATE: &str = "state.candidate.json";
const DISPLACED: &str = "state.displaced.json";
const RECONCILE: &str = "state.reconcile.json";
const GUARD: &str = "state.supersede.json";
const PROOF_LIMIT: usize = 256 * 1024;
const LEGACY_RESIDUE: [&str; 8] = [
    "state.next.json",
    "state.previous.json",
    "state.reconcile.json",
    "state.reconciled-old.json",
    "state.supersede.intent.next.json",
    "state.supersede.next.json",
    "state.supersede.displaced.json",
    "state.archive.json",
];
const PROOF_SLOTS: [RecordSlot; 12] = [
    RecordSlot::Coverage,
    RecordSlot::CatalogIntent,
    RecordSlot::ControlIntent,
    RecordSlot::CatalogReceipt,
    RecordSlot::ControlReceipt,
    RecordSlot::CatalogCommitReadback,
    RecordSlot::ControlCommitReadback,
    RecordSlot::ForwardPairReadback,
    RecordSlot::RollbackPairReadback,
    RecordSlot::SelfCheck,
    RecordSlot::RollbackIntent,
    RecordSlot::RollbackPlan,
];

type Result<T> = std::result::Result<T, PublicationError>;

/// Fixed, content-free failures. An error after a namespace operation preserves
/// its exact remaining slots; it never means that publication did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationError {
    Deadline,
    Invalid,
    Changed,
    Io,
    Poisoned,
}

impl fmt::Display for PublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Deadline => "schema-transition publication deadline reached",
            Self::Invalid => "schema-transition publication evidence is invalid",
            Self::Changed => "schema-transition publication binding changed",
            Self::Io => "schema-transition publication I/O failed",
            Self::Poisoned => "schema-transition publication requires exact reentry",
        })
    }
}

impl std::error::Error for PublicationError {}

impl From<super::RecordError> for PublicationError {
    fn from(_: super::RecordError) -> Self {
        Self::Invalid
    }
}

fn ensure(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(PublicationError::Changed)
    }
}

fn deadline(end: Instant) -> Result<()> {
    if Instant::now() >= SqliteControlStore::effective_runtime_deadline(end) {
        Err(PublicationError::Deadline)
    } else {
        Ok(())
    }
}

fn io_error(_: io::Error) -> PublicationError {
    PublicationError::Io
}

fn publication_io(site: &'static str, error: io::Error) -> PublicationError {
    // Read the error from this failed call only. No paths, retries, last-error
    // queries or additional native operations are used for diagnostics.
    #[cfg(test)]
    eprintln!(
        "schema_transition_publication_io site={site} os={:?}",
        error.raw_os_error()
    );
    #[cfg(not(test))]
    let _ = (site, error);
    PublicationError::Io
}

/// Borrow real held locks. No lock is obtained, retried, recreated or inferred
/// from an owner nonce. The other replacement-group guards stay with the caller.
pub struct JournalLocks<'a> {
    prefix: &'a ExclusiveGuard,
    control_handles: &'a ExclusiveGuard,
    policy_owner: &'a ExclusiveGuard,
}

impl<'a> JournalLocks<'a> {
    pub fn new(
        prefix: &'a ExclusiveGuard,
        control_handles: &'a ExclusiveGuard,
        policy_owner: &'a ExclusiveGuard,
    ) -> Result<Self> {
        let installation =
            JobLockKey::parse("installation-update").map_err(|_| PublicationError::Invalid)?;
        ensure(
            prefix.kind() == &LockKind::MaintenanceJob(installation)
                && control_handles.kind() == &LockKind::ControlHandles
                && policy_owner.kind() == &LockKind::PolicyOwner
                && control_handles.root_identity() == policy_owner.root_identity(),
        )?;
        Ok(Self {
            prefix,
            control_handles,
            policy_owner,
        })
    }

    fn validate(&self, prefix: &Path, control: &Path) -> Result<()> {
        for (guard, root) in [
            (self.prefix, prefix),
            (self.control_handles, control),
            (self.policy_owner, control),
        ] {
            guard
                .validate_current(root)
                .map_err(|_| PublicationError::Changed)?;
        }
        Ok(())
    }
}

/// Native identities are kept in memory and never exposed as authorization.
/// Windows uses the full 128-bit FILE_ID_INFO, not the older 64-bit seal.
#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeIdentity {
    volume: u64,
    file: u128,
}

#[cfg(windows)]
fn identity(file: &File) -> Result<NativeIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_ID_INFO::default();
    let size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
        .map_err(|_| PublicationError::Invalid)?;
    // SAFETY: this borrowed, live File owns the handle. The aligned output has
    // the exact FILE_ID_INFO size. No callback or ownership transfer occurs.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size,
        )
    } == 0
    {
        return Err(PublicationError::Io);
    }
    Ok(NativeIdentity {
        volume: info.VolumeSerialNumber,
        file: u128::from_le_bytes(info.FileId.Identifier),
    })
}

#[cfg(unix)]
fn identity(file: &File) -> Result<NativeIdentity> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().map_err(io_error)?;
    Ok(NativeIdentity {
        volume: meta.dev(),
        file: u128::from(meta.ino()),
    })
}

struct Directory {
    file: File,
    path: PathBuf,
    identity: NativeIdentity,
}

impl Directory {
    fn create_child(&self, name: &str, end: Instant) -> Result<Self> {
        self.validate(end)?;
        deadline(end)?;
        ensure(platform::create_private_directory(&self.path.join(name)).map_err(io_error)?)?;
        let child = self.child(name, end)?;
        self.sync(end)?;
        Ok(child)
    }

    fn open(path: &Path, end: Instant) -> Result<Self> {
        deadline(end)?;
        ordinary(path).map_err(|_| PublicationError::Changed)?;
        platform::validate_private(path).map_err(io_error)?;
        let file = platform::directory(path).map_err(io_error)?;
        let identity = identity(&file)?;
        let result = Self {
            file,
            path: path.to_path_buf(),
            identity,
        };
        result.validate(end)?;
        Ok(result)
    }

    fn child(&self, name: &str, end: Instant) -> Result<Self> {
        self.validate(end)?;
        let path = self.path.join(name);
        ordinary(&path).map_err(|_| PublicationError::Changed)?;
        platform::validate_private(&path).map_err(io_error)?;
        let file = native::directory(self, name).map_err(io_error)?;
        let identity = identity(&file)?;
        let result = Self {
            file,
            path,
            identity,
        };
        self.validate(end)?;
        result.validate(end)?;
        Ok(result)
    }

    fn validate(&self, end: Instant) -> Result<()> {
        deadline(end)?;
        ordinary(&self.path).map_err(|_| PublicationError::Changed)?;
        platform::validate_private(&self.path).map_err(io_error)?;
        let current = platform::directory(&self.path).map_err(io_error)?;
        ensure(identity(&self.file)? == self.identity && identity(&current)? == self.identity)?;
        deadline(end)
    }

    fn read(&self, name: &str, limit: usize, end: Instant) -> Result<Option<Slot>> {
        self.validate(end)?;
        let mut file = match native::read(self, name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.validate(end)?;
                return Ok(None);
            }
            Err(error) => return Err(io_error(error)),
        };
        native::private_file(self, &file).map_err(io_error)?;
        let identity = identity(&file)?;
        let size = file.metadata().map_err(io_error)?.len();
        ensure(size <= limit as u64)?;
        let mut raw = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            deadline(end)?;
            let count = file.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            ensure(raw.len().checked_add(count).is_some_and(|n| n <= limit))?;
            raw.extend_from_slice(&buffer[..count]);
        }
        ensure(file.metadata().map_err(io_error)?.len() == size && raw.len() as u64 == size)?;
        let current = native::read(self, name).map_err(io_error)?;
        ensure(identity == self::identity(&current)?)?;
        self.validate(end)?;
        Ok(Some(Slot {
            file,
            identity,
            raw,
        }))
    }

    fn required(&self, name: &str, limit: usize, end: Instant) -> Result<Slot> {
        self.read(name, limit, end)?
            .ok_or(PublicationError::Changed)
    }

    fn write_new(&self, name: &str, raw: &[u8], end: Instant) -> Result<Slot> {
        self.validate(end)?;
        let mut file = native::create(self, name).map_err(io_error)?;
        for chunk in raw.chunks(8192) {
            deadline(end)?;
            file.write_all(chunk).map_err(io_error)?;
        }
        fault(if name == CANDIDATE {
            Fault::CandidateWritten
        } else {
            Fault::ProofWritten
        })?;
        deadline(end)?;
        file.sync_all()
            .map_err(|error| publication_io("record_flush", error))?;
        let created = identity(&file)?;
        drop(file);
        self.sync(end)?;
        let slot = self.required(name, raw.len(), end)?;
        ensure(slot.identity == created && slot.raw == raw)?;
        Ok(slot)
    }

    fn flush_retained(&self, name: &str, expected: &Slot, end: Instant) -> Result<()> {
        self.matches(name, expected, end)?;
        deadline(end)?;
        let file =
            native::writable(self, name).map_err(|error| publication_io("retained_open", error))?;
        ensure(identity(&file)? == expected.identity)?;
        deadline(end)?;
        file.sync_all()
            .map_err(|error| publication_io("retained_flush", error))?;
        drop(file);
        self.sync(end)?;
        self.matches(name, expected, end)
    }

    fn matches(&self, name: &str, expected: &Slot, end: Instant) -> Result<()> {
        ensure(identity(&expected.file)? == expected.identity)?;
        let observed = self.required(name, expected.raw.len(), end)?;
        ensure(observed.identity == expected.identity && observed.raw == expected.raw)
    }

    fn remove(&self, name: &str, expected: Slot, end: Instant) -> Result<()> {
        self.matches(name, &expected, end)?;
        let limit = expected.raw.len();
        // Close the acknowledged predecessor before unlinking it. Windows
        // DeleteFile cannot confirm absence while this handle is still open.
        // Every other handle to this slot was released by the publisher.
        drop(expected);
        deadline(end)?;
        native::remove(self, name).map_err(io_error)?;
        self.sync(end)?;
        ensure(self.read(name, limit, end)?.is_none())
    }

    fn sync(&self, end: Instant) -> Result<()> {
        deadline(end)?;
        native::sync(self).map_err(io_error)?;
        self.validate(end)
    }
}

struct Slot {
    file: File,
    identity: NativeIdentity,
    raw: Vec<u8>,
}

struct Immutable {
    directory: Directory,
    name: &'static str,
    slot: Slot,
}

impl Immutable {
    fn validate(&self, end: Instant) -> Result<()> {
        self.directory.matches(self.name, &self.slot, end)
    }
}

struct RecordPins {
    present: Vec<Immutable>,
    absent_manifests: Vec<Directory>,
}

impl RecordPins {
    fn validate(&self, end: Instant) -> Result<()> {
        for file in &self.present {
            file.validate(end)?;
        }
        for directory in &self.absent_manifests {
            ensure(directory.read("manifest.json", PROOF_LIMIT, end)?.is_none())?;
        }
        Ok(())
    }
}

/// The ACK concerns only the exact state bytes and their owned staging cleanup.
/// It is not an acknowledgement of SQL, a package switch, or final acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    Published,
    ReadBack,
}

/// Initialize only the native journal. The retained locks exclude concurrent
/// legitimate writers, but do not supply package, process or database authority.
pub(super) fn initialize(
    invocation: &Invocation,
    admission: &AdmissionV2,
    locks: JournalLocks<'_>,
    end: Instant,
) -> Result<Publication> {
    let end = SqliteControlStore::effective_runtime_deadline(end);
    deadline(end)?;
    ensure(matches!(invocation.action, InternalAction::Prepare { .. }))?;
    invocation.validate_relations(admission)?;
    ensure(admission.encode()? == admission.raw_bytes())?;
    locks.validate(&invocation.prefix, &invocation.control_root)?;
    ensure(
        locks.prefix.root_identity().control_id().as_str() == admission.record.prefix.identity
            && locks.control_handles.root_identity().control_id().as_str()
                == admission.record.control_root.identity,
    )?;
    let prefix = Directory::open(&invocation.prefix, end)?;
    let control = Directory::open(&invocation.control_root, end)?;
    for name in [
        "schema-transition-finalize.json",
        "schema-transition-finalize.next.json",
        "schema-transition-finalize.displaced.json",
    ] {
        ensure(control.read(name, 8192, end)?.is_none())?;
    }
    let initial = StateV2::initial(admission)?;
    initial.validate_records(&[], &[], admission)?;
    let guard = SupersedeGuardV2::initial(admission, &initial)?;
    let update_exists = exists(&prefix.path.join("update"))?;
    if !update_exists {
        ensure(matches!(
            admission.record.old_layout,
            OldJournalLayout::Absent { .. }
        ))?;
    }
    let update = if update_exists {
        prefix.child("update", end)?
    } else {
        prefix.create_child("update", end)?
    };
    for name in LEGACY_RESIDUE {
        ensure(update.read(name, MAX_RECORD_BYTES, end)?.is_none())?;
    }
    let id = &admission.record.update_id;
    let run_exists = exists(&update.path.join(id))?;
    let guard_present = update.read(GUARD, MAX_RECORD_BYTES, end)?;
    let guarded_at_entry = guard_present.is_some();
    if !run_exists {
        ensure(guard_present.is_none())?;
        // An absent-layout retry cannot claim an unrelated empty update root.
        ensure(
            !update_exists
                || !matches!(admission.record.old_layout, OldJournalLayout::Absent { .. }),
        )?;
    }
    let old_run = match &admission.record.old_layout {
        OldJournalLayout::Absent { .. } => None,
        OldJournalLayout::TerminalV1 {
            update_id,
            run_identity,
            ..
        } => {
            let old = update.child(update_id, end)?;
            ensure(
                RootIdentity::read(&old.path)
                    .map_err(|_| PublicationError::Changed)?
                    .control_id()
                    .as_str()
                    == run_identity,
            )?;
            Some(old)
        }
    };
    let original_active = update.read(ACTIVE, MAX_RECORD_BYTES, end)?;
    if guard_present.is_none() {
        initial_old_active(admission, old_run.as_ref(), original_active.as_ref())?;
    } else {
        ensure(run_exists)?;
    }
    let run = if run_exists {
        let run = update.child(id, end)?;
        let bound = run.required("admission.json", MAX_RECORD_BYTES, end)?;
        ensure(bound.raw == admission.raw_bytes())?;
        run
    } else {
        update.create_child(id, end)?
    };
    initial_layout(&run, end)?;
    if matches!(admission.record.old_layout, OldJournalLayout::Absent { .. }) {
        for entry in fs::read_dir(&update.path).map_err(io_error)? {
            deadline(end)?;
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            ensure(name == id.as_str() || name == ACTIVE || name == GUARD)?;
        }
    }
    if let Some(published) = &guard_present {
        ensure(
            published.raw == guard.raw_bytes()
                && run
                    .read("guard.ready.json", MAX_RECORD_BYTES, end)?
                    .is_none(),
        )?;
        ensure(
            run.required("state.initial.json", MAX_RECORD_BYTES, end)?
                .raw
                == initial.raw_bytes(),
        )?;
    }
    let admitted = initial_record(&run, "admission.json", admission.raw_bytes(), end)?;
    fault(Fault::InitialAdmission)?;
    let old_state = if let Some(old_run) = &old_run {
        let prior = if exists(&run.path.join("prior"))? {
            run.child("prior", end)?
        } else {
            ensure(guard_present.is_none())?;
            run.create_child("prior", end)?
        };
        for entry in fs::read_dir(&prior.path).map_err(io_error)? {
            deadline(end)?;
            ensure(entry.map_err(io_error)?.file_name() == "state.v1.raw")?;
        }
        let recorded = prior.read("state.v1.raw", MAX_RECORD_BYTES, end)?;
        let bytes = if let Some(recorded) = &recorded {
            recorded.raw.as_slice()
        } else {
            ensure(guard_present.is_none())?;
            original_active
                .as_ref()
                .ok_or(PublicationError::Changed)?
                .raw
                .as_slice()
        };
        let OldJournalLayout::TerminalV1 { run_identity, .. } = &admission.record.old_layout else {
            return Err(PublicationError::Invalid);
        };
        guard.validate_relations(
            admission,
            initial.raw_bytes(),
            Some(OldTerminalInput {
                state: bytes,
                run_path: &old_run.path,
                run_identity,
            }),
        )?;
        Some(Immutable {
            slot: initial_record(&prior, "state.v1.raw", bytes, end)?,
            directory: prior,
            name: "state.v1.raw",
        })
    } else {
        ensure(!exists(&run.path.join("prior"))?)?;
        guard.validate_relations(admission, initial.raw_bytes(), None)?;
        None
    };
    let initial_slot = initial_record(&run, "state.initial.json", initial.raw_bytes(), end)?;
    fault(Fault::InitialState)?;
    let ready = run.read("guard.ready.json", MAX_RECORD_BYTES, end)?;
    let final_guard = if let Some(published) = guard_present {
        ensure(ready.is_none() && published.raw == guard.raw_bytes())?;
        update.flush_retained(GUARD, &published, end)?;
        published
    } else {
        ensure(run.read(CANDIDATE, MAX_RECORD_BYTES, end)?.is_none())?;
        ensure(run.read(DISPLACED, MAX_RECORD_BYTES, end)?.is_none())?;
        let ready = initial_record(&run, "guard.ready.json", guard.raw_bytes(), end)?;
        fault(Fault::InitialGuardReady)?;
        initial_recheck_active(&update, original_active.as_ref(), end)?;
        locks.validate(&prefix.path, &control.path)?;
        run.matches("admission.json", &admitted, end)?;
        run.matches("state.initial.json", &initial_slot, end)?;
        if let Some(old) = &old_state {
            old.validate(end)?;
        }
        run.matches("guard.ready.json", &ready, end)?;
        deadline(end)?;
        native::move_new(&run, "guard.ready.json", &update, GUARD).map_err(io_error)?;
        update.sync(end)?;
        run.sync(end)?;
        let published = update.required(GUARD, MAX_RECORD_BYTES, end)?;
        ensure(published.identity == ready.identity && published.raw == guard.raw_bytes())?;
        update.flush_retained(GUARD, &published, end)?;
        published
    };
    fault(Fault::InitialGuardPublished)?;
    if !guarded_at_entry {
        initial_recheck_active(&update, original_active.as_ref(), end)?;
    }
    let mut active = update.read(ACTIVE, MAX_RECORD_BYTES, end)?;
    let mut candidate = run.read(CANDIDATE, MAX_RECORD_BYTES, end)?;
    let mut displaced = run.read(DISPLACED, MAX_RECORD_BYTES, end)?;
    let already_current = active
        .as_ref()
        .is_some_and(|slot| slot.raw == initial.raw_bytes());
    let old_bytes = old_state.as_ref().map(|old| old.slot.raw.as_slice());
    if let Some(original) = &original_active
        && original.raw == initial.raw_bytes()
    {
        ensure(
            already_current
                && active
                    .as_ref()
                    .is_some_and(|now| now.identity == original.identity),
        )?;
    }
    if already_current {
        ensure(candidate.is_none() || displaced.is_none())?;
        for retained in [candidate.as_ref(), displaced.as_ref()]
            .into_iter()
            .flatten()
        {
            ensure(old_bytes == Some(retained.raw.as_slice()))?;
        }
    } else {
        if let Some(active) = &active {
            ensure(displaced.is_none() && old_bytes == Some(active.raw.as_slice()))?;
            if let Some(original) = &original_active {
                ensure(active.identity == original.identity && active.raw == original.raw)?;
            }
        } else if old_bytes.is_some() {
            ensure(
                displaced
                    .as_ref()
                    .is_some_and(|slot| Some(slot.raw.as_slice()) == old_bytes)
                    && candidate
                        .as_ref()
                        .is_some_and(|slot| slot.raw == initial.raw_bytes()),
            )?;
        } else {
            ensure(displaced.is_none())?;
        }
        if let Some(staged) = &candidate {
            ensure(staged.raw == initial.raw_bytes())?;
            run.flush_retained(CANDIDATE, staged, end)?;
        } else {
            candidate = Some(run.write_new(CANDIDATE, initial.raw_bytes(), end)?);
        }
        fault(Fault::InitialCandidate)?;
        let staged = candidate.take().ok_or(PublicationError::Changed)?;
        let next_identity = staged.identity;
        update.matches(GUARD, &final_guard, end)?;
        run.matches("admission.json", &admitted, end)?;
        run.matches("state.initial.json", &initial_slot, end)?;
        if let Some(old) = &old_state {
            old.validate(end)?;
        }
        initial_recheck_active(&update, active.as_ref(), end)?;
        locks.validate(&prefix.path, &control.path)?;
        #[cfg(windows)]
        let replacement_pin = {
            let pin = native::metadata_pin(&run, CANDIDATE).map_err(io_error)?;
            ensure(identity(&pin)? == next_identity)?;
            drop(staged);
            pin
        };
        deadline(end)?;
        if active.is_some() {
            native::replace(&update, ACTIVE, &run, CANDIDATE, DISPLACED).map_err(io_error)?;
        } else {
            native::move_new(&run, CANDIDATE, &update, ACTIVE).map_err(io_error)?;
        }
        fault(Fault::InitialActive)?;
        let current = update.required(ACTIVE, MAX_RECORD_BYTES, end)?;
        ensure(current.identity == next_identity && current.raw == initial.raw_bytes())?;
        update.flush_retained(ACTIVE, &current, end)?;
        #[cfg(windows)]
        ensure(identity(&replacement_pin)? == current.identity)?;
        active = Some(current);
        candidate = run.read(CANDIDATE, MAX_RECORD_BYTES, end)?;
        displaced = run.read(DISPLACED, MAX_RECORD_BYTES, end)?;
    }
    let active = active.ok_or(PublicationError::Changed)?;
    // No read handle to the old active may survive its final deletion on
    // Windows. The separately retained immutable prior copy is not deleted.
    drop(original_active);
    ensure(candidate.is_none() || displaced.is_none())?;
    for (name, slot) in [(CANDIDATE, candidate), (DISPLACED, displaced)] {
        if let Some(slot) = slot {
            ensure(old_bytes == Some(slot.raw.as_slice()))?;
            run.remove(name, slot, end)?;
        }
    }
    update.flush_retained(ACTIVE, &active, end)?;
    update.matches(GUARD, &final_guard, end)?;
    run.matches("admission.json", &admitted, end)?;
    run.matches("state.initial.json", &initial_slot, end)?;
    locks.validate(&prefix.path, &control.path)?;
    initial_layout(&run, end)?;
    prefix.validate(end)?;
    control.validate(end)?;
    if let Some(old) = &old_state {
        old.validate(end)?;
    }
    Ok(if already_current {
        Publication::ReadBack
    } else {
        Publication::Published
    })
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(error)),
    }
}

fn initial_record(directory: &Directory, name: &str, raw: &[u8], end: Instant) -> Result<Slot> {
    match directory.read(name, MAX_RECORD_BYTES, end)? {
        Some(slot) => {
            ensure(slot.raw == raw)?;
            directory.flush_retained(name, &slot, end)?;
            Ok(slot)
        }
        None => directory.write_new(name, raw, end),
    }
}

fn initial_old_active(
    admission: &AdmissionV2,
    old_run: Option<&Directory>,
    active: Option<&Slot>,
) -> Result<()> {
    match &admission.record.old_layout {
        OldJournalLayout::Absent { .. } => ensure(active.is_none() && old_run.is_none()),
        OldJournalLayout::TerminalV1 { run_identity, .. } => {
            let old = old_run.ok_or(PublicationError::Changed)?;
            let active = active.ok_or(PublicationError::Changed)?;
            admission.compare_old_layout(Some(OldTerminalInput {
                state: &active.raw,
                run_path: &old.path,
                run_identity,
            }))?;
            Ok(())
        }
    }
}

fn initial_recheck_active(update: &Directory, active: Option<&Slot>, end: Instant) -> Result<()> {
    match active {
        Some(slot) => update.matches(ACTIVE, slot, end),
        None => ensure(update.read(ACTIVE, MAX_RECORD_BYTES, end)?.is_none()),
    }
}

fn initial_layout(run: &Directory, end: Instant) -> Result<()> {
    run.validate(end)?;
    for entry in fs::read_dir(&run.path).map_err(io_error)? {
        deadline(end)?;
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(PublicationError::Changed)?;
        let meta = fs::symlink_metadata(entry.path()).map_err(io_error)?;
        ordinary(&entry.path()).map_err(|_| PublicationError::Changed)?;
        ensure(if name == "prior" {
            meta.is_dir()
        } else {
            matches!(
                name,
                "admission.json"
                    | "state.initial.json"
                    | "guard.ready.json"
                    | CANDIDATE
                    | DISPLACED
            ) && meta.is_file()
        })?;
    }
    run.validate(end)
}

/// A retained, same-request journal receiver. Failures poison this receiver;
/// reentry must reopen the actual slots under fresh validated held capabilities.
pub struct Journal<'a> {
    locks: JournalLocks<'a>,
    end: Instant,
    prefix: Directory,
    control: Directory,
    update: Directory,
    run: Directory,
    admission: AdmissionV2,
    immutable: Vec<Immutable>,
    old_run: Option<Directory>,
    poisoned: Cell<bool>,
}

struct PoisonOnDrop<'a> {
    flag: &'a Cell<bool>,
    armed: bool,
}

impl Drop for PoisonOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.flag.set(true);
        }
    }
}

impl<'a> Journal<'a> {
    pub(super) fn open(
        invocation: &Invocation,
        locks: JournalLocks<'a>,
        end: Instant,
    ) -> Result<Self> {
        let end = SqliteControlStore::effective_runtime_deadline(end);
        deadline(end)?;
        let InternalAction::Continue { update_id } = &invocation.action else {
            return Err(PublicationError::Invalid);
        };
        locks.validate(&invocation.prefix, &invocation.control_root)?;
        let prefix = Directory::open(&invocation.prefix, end)?;
        let control = Directory::open(&invocation.control_root, end)?;
        let update = prefix.child("update", end)?;
        let run = update.child(update_id, end)?;
        let admission_slot = run.required("admission.json", MAX_RECORD_BYTES, end)?;
        let admission = AdmissionV2::decode(&admission_slot.raw)?;
        invocation.validate_relations(&admission)?;
        ensure(
            locks.prefix.root_identity().control_id().as_str() == admission.record.prefix.identity
                && locks.control_handles.root_identity().control_id().as_str()
                    == admission.record.control_root.identity,
        )?;
        let guard_slot = update.required(GUARD, MAX_RECORD_BYTES, end)?;
        let guard = SupersedeGuardV2::decode(&guard_slot.raw)?;
        let initial_slot = run.required("state.initial.json", MAX_RECORD_BYTES, end)?;
        let initial = StateV2::decode(&initial_slot.raw, &admission)?;
        let header = Header::read(&initial)?;
        ensure(header.seq == 1 && initial.encode(&admission)? == initial.raw_bytes())?;
        initial.validate_records(&[], &[], &admission)?;
        let mut immutable = Vec::new();
        let old_run = match &admission.record.old_layout {
            OldJournalLayout::Absent { .. } => {
                guard.validate_relations(&admission, initial.raw_bytes(), None)?;
                // The already durable admission records the original absence;
                // this receiver never reinterprets the now-present update root.
                None
            }
            OldJournalLayout::TerminalV1 {
                update_id: old_id,
                run_identity,
                ..
            } => {
                let old_run = update.child(old_id, end)?;
                ensure(
                    RootIdentity::read(&old_run.path)
                        .map_err(|_| PublicationError::Changed)?
                        .control_id()
                        .as_str()
                        == run_identity,
                )?;
                let prior = run.child("prior", end)?;
                let state = prior.required("state.v1.raw", MAX_RECORD_BYTES, end)?;
                guard.validate_relations(
                    &admission,
                    initial.raw_bytes(),
                    Some(OldTerminalInput {
                        state: &state.raw,
                        run_path: &old_run.path,
                        run_identity,
                    }),
                )?;
                immutable.push(Immutable {
                    directory: prior,
                    name: "state.v1.raw",
                    slot: state,
                });
                Some(old_run)
            }
        };
        immutable.push(Immutable {
            directory: update.child(update_id, end)?,
            name: "admission.json",
            slot: admission_slot,
        });
        immutable.push(Immutable {
            directory: update.child(update_id, end)?,
            name: "state.initial.json",
            slot: initial_slot,
        });
        immutable.push(Immutable {
            directory: prefix.child("update", end)?,
            name: GUARD,
            slot: guard_slot,
        });
        let result = Self {
            locks,
            end,
            prefix,
            control,
            update,
            run,
            admission,
            immutable,
            old_run,
            poisoned: Cell::new(false),
        };
        result.check()?;
        // No ordinary v1 recovery, directory creation, SQL or repair is called.
        match result.update.read(ACTIVE, MAX_RECORD_BYTES, end)? {
            Some(active) => {
                result.decode_current(&active)?;
            }
            None => {
                // ReplaceFileW can fail after saving the old name (1177).
                // Only both exact adjacent images permit subsequent recovery;
                // there is no initial-state fallback or history reconstruction.
                let previous = result.run.required(DISPLACED, MAX_RECORD_BYTES, end)?;
                let candidate = result.run.required(CANDIDATE, MAX_RECORD_BYTES, end)?;
                let previous = result.decode_current(&previous)?;
                let next = StateV2::decode(&candidate.raw, &result.admission)?;
                next.validate_chain(&previous, &result.admission)?;
            }
        }
        ensure(result.run.read(RECONCILE, MAX_RECORD_BYTES, end)?.is_none())?;
        Ok(result)
    }

    pub fn admission(&self) -> &AdmissionV2 {
        &self.admission
    }

    /// Read the actual current bytes. Referenced payloads are checked against
    /// the exact files when passed to publish; this does not grant execution.
    pub fn current(&self) -> Result<StateV2> {
        self.receive(|| {
            fault(Fault::CurrentRead)?;
            let slot = self.update.required(ACTIVE, MAX_RECORD_BYTES, self.end)?;
            self.decode_current(&slot)
        })
    }

    fn decode_current(&self, slot: &Slot) -> Result<StateV2> {
        let state = StateV2::decode(&slot.raw, &self.admission)?;
        if Header::read(&state)?.seq == 1 {
            let initial = self
                .run
                .required("state.initial.json", MAX_RECORD_BYTES, self.end)?;
            ensure(slot.raw == initial.raw)?;
        }
        Ok(state)
    }

    /// Validate the full reducer before any new bytes. Immutable proofs are
    /// create-only; manifests must already exist under their actual C parents.
    /// A lost ACK reuses exactly this predecessor/successor, never a new effect.
    pub fn publish(
        &mut self,
        previous: &StateV2,
        next: &StateV2,
        evidence: SuccessorEvidence<'_>,
    ) -> Result<Publication> {
        self.receive(|| self.publish_inner(previous, next, evidence, None))
    }

    /// Resolve the one retained adjacent publication using the actual disk
    /// slots. None means there is no pending publication to acknowledge. The
    /// supplied payload sets/readback still belong to the retained executor.
    pub fn reconcile(&mut self, evidence: SuccessorEvidence<'_>) -> Result<Option<Publication>> {
        self.receive(|| self.reconcile_inner(evidence))
    }

    fn receive<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut poison = PoisonOnDrop {
            flag: &self.poisoned,
            armed: true,
        };
        // Arm before even the entry checks: restoring an external file after a
        // refusal cannot revive a receiver that observed changed evidence.
        self.check()?;
        let result = operation();
        poison.armed = result.is_err();
        result
    }

    fn reconcile_inner(&self, evidence: SuccessorEvidence<'_>) -> Result<Option<Publication>> {
        let active = self.update.read(ACTIVE, MAX_RECORD_BYTES, self.end)?;
        let candidate = self.run.read(CANDIDATE, MAX_RECORD_BYTES, self.end)?;
        let displaced = self.run.read(DISPLACED, MAX_RECORD_BYTES, self.end)?;
        let Some(active) = active else {
            let candidate = candidate.ok_or(PublicationError::Changed)?;
            let displaced = displaced.ok_or(PublicationError::Changed)?;
            let previous = self.decode_current(&displaced)?;
            let next = StateV2::decode(&candidate.raw, &self.admission)?;
            return self
                .publish_inner(&previous, &next, evidence, Some((candidate, displaced)))
                .map(Some);
        };
        ensure(candidate.is_none() || displaced.is_none())?;
        let current = self.decode_current(&active)?;
        match (candidate, displaced) {
            (None, None) => {
                ensure(evidence.effect_readback.is_none())?;
                current.validate_records(
                    evidence.current.proofs,
                    evidence.current.manifests,
                    &self.admission,
                )?;
                let pins = self.records(&current, evidence.current, false)?;
                self.proof_inventory(evidence.current)?;
                self.flush_proofs(evidence.current)?;
                self.update.flush_retained(ACTIVE, &active, self.end)?;
                pins.validate(self.end)?;
                self.update.matches(ACTIVE, &active, self.end)?;
                self.check()?;
                Ok(None)
            }
            (Some(slot), None) => {
                let other = StateV2::decode(&slot.raw, &self.admission)?;
                drop(slot);
                drop(active);
                let (previous, next) = if current.validate_chain(&other, &self.admission).is_ok() {
                    (&other, &current)
                } else {
                    (&current, &other)
                };
                self.publish_inner(previous, next, evidence, None).map(Some)
            }
            (None, Some(slot)) => {
                let previous = StateV2::decode(&slot.raw, &self.admission)?;
                drop(slot);
                drop(active);
                self.publish_inner(&previous, &current, evidence, None)
                    .map(Some)
            }
            (Some(_), Some(_)) => Err(PublicationError::Changed),
        }
    }

    fn check(&self) -> Result<()> {
        if self.poisoned.get() {
            return Err(PublicationError::Poisoned);
        }
        fault(Fault::ReceiverCheck)?;
        deadline(self.end)?;
        self.locks.validate(&self.prefix.path, &self.control.path)?;
        self.prefix.validate(self.end)?;
        self.control.validate(self.end)?;
        self.update.validate(self.end)?;
        self.run.validate(self.end)?;
        if let Some(old_run) = &self.old_run {
            old_run.validate(self.end)?;
        }
        for record in &self.immutable {
            record.validate(self.end)?;
        }
        for name in LEGACY_RESIDUE {
            ensure(
                self.update
                    .read(name, MAX_RECORD_BYTES, self.end)?
                    .is_none(),
            )?;
        }
        for name in [
            "schema-transition-finalize.json",
            "schema-transition-finalize.next.json",
            "schema-transition-finalize.displaced.json",
        ] {
            // C-root finalization has a separate, higher-priority consumer.
            // This receiver cannot recreate U or advance its obsolete state.
            ensure(self.control.read(name, 8192, self.end)?.is_none())?;
        }
        self.layout()?;
        deadline(self.end)
    }

    fn layout(&self) -> Result<()> {
        // No recursive scan and no cleanup. Fixed U names only; enumeration
        // never supplies an input path for writes. Revalidate the pinned U after
        // the bounded read even on POSIX where a held directory can be renamed.
        for entry in fs::read_dir(&self.run.path).map_err(io_error)? {
            deadline(self.end)?;
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(PublicationError::Changed)?;
            let directory = matches!(name, "prior" | "package" | "metadata");
            ensure(
                directory
                    || matches!(
                        name,
                        "admission.json"
                            | "state.initial.json"
                            | "guard.ready.json"
                            | CANDIDATE
                            | DISPLACED
                            | RECONCILE
                    )
                    || PROOF_SLOTS.into_iter().any(|slot| slot.filename() == name),
            )?;
            let kind = entry.file_type().map_err(io_error)?;
            ensure(if directory {
                kind.is_dir()
            } else {
                kind.is_file()
            })?;
        }
        self.run.validate(self.end)
    }

    fn publish_inner(
        &self,
        previous: &StateV2,
        next: &StateV2,
        evidence: SuccessorEvidence<'_>,
        retained_pair: Option<(Slot, Slot)>,
    ) -> Result<Publication> {
        ensure(
            previous.encode(&self.admission)? == previous.raw_bytes()
                && next.encode(&self.admission)? == next.raw_bytes(),
        )?;
        let previous_records = evidence.previous;
        let current_records = evidence.current;
        next.validate_successor(previous, evidence, &self.admission)?;
        // validate_successor above validates the immutable historical manifest
        // payloads too. Their physical file may already have been deleted by
        // the predecessor's owned_delete intent; only next describes the ACK.
        let previous_pins = self.proof_files(previous_records, false)?;
        // Check every destination before creating even the first new record.
        let existing_pins = self.records(next, current_records, true)?;
        self.proof_inventory(current_records)?;
        ensure(
            self.run
                .read(RECONCILE, MAX_RECORD_BYTES, self.end)?
                .is_none(),
        )?;
        let active = self.update.read(ACTIVE, MAX_RECORD_BYTES, self.end)?;
        if let Some(active) = &active {
            self.decode_current(active)?;
        }
        let (mut candidate, displaced) = match retained_pair {
            Some((candidate, displaced)) => {
                ensure(active.is_none())?;
                self.run.matches(CANDIDATE, &candidate, self.end)?;
                self.run.matches(DISPLACED, &displaced, self.end)?;
                (Some(candidate), Some(displaced))
            }
            None => (
                self.run.read(CANDIDATE, MAX_RECORD_BYTES, self.end)?,
                self.run.read(DISPLACED, MAX_RECORD_BYTES, self.end)?,
            ),
        };
        let was_current = active
            .as_ref()
            .is_some_and(|slot| slot.raw == next.raw_bytes());
        let missing_active = active.is_none();
        let mut next_identity = active
            .as_ref()
            .or(candidate.as_ref())
            .ok_or(PublicationError::Changed)?
            .identity;
        let previous_identity = if was_current {
            candidate
                .as_ref()
                .or(displaced.as_ref())
                .map(|slot| slot.identity)
        } else {
            active
                .as_ref()
                .or(displaced.as_ref())
                .map(|slot| slot.identity)
        };
        if missing_active {
            let staged = candidate.as_ref().ok_or(PublicationError::Changed)?;
            let prior = displaced.as_ref().ok_or(PublicationError::Changed)?;
            ensure(staged.raw == next.raw_bytes() && prior.raw == previous.raw_bytes())?;
            self.decode_current(prior)?;
        } else if was_current {
            ensure(
                candidate
                    .as_ref()
                    .is_none_or(|s| s.raw == previous.raw_bytes()),
            )?;
            ensure(
                displaced
                    .as_ref()
                    .is_none_or(|s| s.raw == previous.raw_bytes()),
            )?;
            ensure(candidate.is_none() || displaced.is_none())?;
        } else {
            ensure(
                active
                    .as_ref()
                    .is_some_and(|slot| slot.raw == previous.raw_bytes()),
            )?;
            ensure(candidate.as_ref().is_none_or(|s| s.raw == next.raw_bytes()))?;
            ensure(displaced.is_none())?;
        }
        for proof in current_records.proofs {
            let name = proof_key(proof)?.filename();
            match self.run.read(name, PROOF_LIMIT, self.end)? {
                Some(slot) => {
                    ensure(slot.raw == proof.raw_bytes())?;
                    // Complete bytes can survive a failed flush. Their presence
                    // is never the durable-write acknowledgement.
                    self.run.flush_retained(name, &slot, self.end)?;
                    fault(Fault::RetainedProofFlushed)?;
                }
                None => {
                    // Active or already staged state must have all its proofs.
                    ensure(!was_current && candidate.is_none())?;
                    self.check()?;
                    self.run.write_new(name, proof.raw_bytes(), self.end)?;
                    fault(Fault::ProofFlushed)?;
                }
            }
        }
        let current_pins = self.records(next, current_records, false)?;
        for pin in &previous_pins {
            pin.validate(self.end)?;
        }
        existing_pins.validate(self.end)?;
        self.check()?;
        #[cfg(windows)]
        let mut replacement_pin = None;
        if !was_current {
            let staged = match candidate.take() {
                Some(slot) => {
                    self.run.flush_retained(CANDIDATE, &slot, self.end)?;
                    fault(Fault::RetainedCandidateFlushed)?;
                    slot
                }
                None => self.run.write_new(CANDIDATE, next.raw_bytes(), self.end)?,
            };
            next_identity = staged.identity;
            fault(Fault::CandidateFlushed)?;
            if let Some(active) = &active {
                self.update.matches(ACTIVE, active, self.end)?;
            } else {
                ensure(
                    self.update
                        .read(ACTIVE, MAX_RECORD_BYTES, self.end)?
                        .is_none(),
                )?;
                self.run.matches(
                    DISPLACED,
                    displaced.as_ref().ok_or(PublicationError::Changed)?,
                    self.end,
                )?;
            }
            self.run.matches(CANDIDATE, &staged, self.end)?;
            self.check()?;
            #[cfg(windows)]
            {
                // ReplaceFileW opens the replacement without sharing. Retain
                // identity continuously while relinquishing only data access.
                deadline(self.end)?;
                let metadata = native::metadata_pin(&self.run, CANDIDATE)
                    .map_err(|error| publication_io("replacement_metadata_pin", error))?;
                ensure(
                    identity(&metadata)? == staged.identity
                        && identity(&staged.file)? == staged.identity,
                )?;
                replacement_pin = Some(metadata);
                drop(staged);
            }
            deadline(self.end)?;
            if missing_active {
                native::move_new(&self.run, CANDIDATE, &self.update, ACTIVE)
                    .map_err(|error| publication_io("install_retained_candidate", error))?;
            } else {
                #[cfg(test)]
                self.fault_after_displacement()?;
                native::replace(&self.update, ACTIVE, &self.run, CANDIDATE, DISPLACED)
                    .map_err(|error| publication_io("replace_active", error))?;
            }
            fault(Fault::Exchanged)?;
        }
        self.check()?;
        let current = self.update.required(ACTIVE, MAX_RECORD_BYTES, self.end)?;
        ensure(current.raw == next.raw_bytes() && current.identity == next_identity)?;
        // POSIX exchange leaves the old current in candidate until this move.
        // Windows ReplaceFileW places it directly in displaced.
        if let Some(old) = self.run.read(CANDIDATE, MAX_RECORD_BYTES, self.end)? {
            ensure(old.raw == previous.raw_bytes() && Some(old.identity) == previous_identity)?;
            ensure(
                self.run
                    .read(DISPLACED, MAX_RECORD_BYTES, self.end)?
                    .is_none(),
            )?;
            self.run.matches(CANDIDATE, &old, self.end)?;
            self.check()?;
            native::move_new(&self.run, CANDIDATE, &self.run, DISPLACED).map_err(io_error)?;
            fault(Fault::DisplacedStored)?;
        }
        self.flush_active(&current)?;
        #[cfg(windows)]
        if let Some(metadata) = &replacement_pin {
            ensure(identity(metadata)? == current.identity)?;
        }
        self.update.sync(self.end)?;
        self.run.sync(self.end)?;
        self.records(next, current_records, false)?;
        self.proof_inventory(current_records)?;
        for pin in &previous_pins {
            pin.validate(self.end)?;
        }
        current_pins.validate(self.end)?;
        self.update.matches(ACTIVE, &current, self.end)?;
        self.check()?;
        fault(Fault::ReadBack)?;
        // Keep the old active handle through new-active validation and flush;
        // release all predecessor handles only before its acknowledged unlink.
        drop(active);
        drop(candidate);
        drop(displaced);
        // Removal follows a successful exact readback and affects only this
        // acknowledged predecessor. No proof, directory or unknown slot is swept.
        if let Some(old) = self.run.read(DISPLACED, MAX_RECORD_BYTES, self.end)? {
            ensure(old.raw == previous.raw_bytes() && Some(old.identity) == previous_identity)?;
            self.run.remove(DISPLACED, old, self.end)?;
        }
        self.update.matches(ACTIVE, &current, self.end)?;
        self.check()?;
        #[cfg(windows)]
        {
            if let Some(metadata) = &replacement_pin {
                ensure(identity(metadata)? == current.identity)?;
            }
            drop(replacement_pin);
        }
        Ok(if was_current {
            Publication::ReadBack
        } else {
            Publication::Published
        })
    }

    #[cfg(test)]
    fn fault_after_displacement(&self) -> Result<()> {
        let injected = FAILURE.with(|slot| slot.get() == Some(Fault::ActiveDisplaced));
        if injected {
            // Simulate the documented partial native replacement with real
            // no-replace moves; this is not a production fallback for ReplaceFileW.
            deadline(self.end)?;
            native::move_new(&self.update, ACTIVE, &self.run, DISPLACED).map_err(io_error)?;
            self.update.sync(self.end)?;
            self.run.sync(self.end)?;
            fault(Fault::ActiveDisplaced)?;
        }
        Ok(())
    }

    fn flush_active(&self, expected: &Slot) -> Result<()> {
        self.update.matches(ACTIVE, expected, self.end)?;
        deadline(self.end)?;
        let file = native::writable(&self.update, ACTIVE)
            .map_err(|error| publication_io("active_flush_open", error))?;
        ensure(identity(&file)? == expected.identity)?;
        deadline(self.end)?;
        file.sync_all()
            .map_err(|error| publication_io("active_flush", error))?;
        self.update.matches(ACTIVE, expected, self.end)
    }

    fn flush_proofs(&self, records: RecordSet<'_>) -> Result<()> {
        for proof in records.proofs {
            let name = proof_key(proof)?.filename();
            let slot = self.run.required(name, PROOF_LIMIT, self.end)?;
            ensure(slot.raw == proof.raw_bytes())?;
            self.run.flush_retained(name, &slot, self.end)?;
            fault(Fault::RetainedProofFlushed)?;
        }
        Ok(())
    }

    fn proof_inventory(&self, records: RecordSet<'_>) -> Result<()> {
        for slot in PROOF_SLOTS {
            if let Some(actual) = self.run.read(slot.filename(), PROOF_LIMIT, self.end)? {
                let mut matching = false;
                for proof in records.proofs {
                    if proof_key(proof)? == slot {
                        ensure(actual.raw == proof.raw_bytes())?;
                        matching = true;
                    }
                }
                ensure(matching)?;
            }
        }
        Ok(())
    }

    fn records(
        &self,
        state: &StateV2,
        records: RecordSet<'_>,
        allow_new: bool,
    ) -> Result<RecordPins> {
        let mut pins = RecordPins {
            present: self.proof_files(records, allow_new)?,
            absent_manifests: Vec::new(),
        };
        let bindings: ManifestBindings =
            serde_json::from_slice(state.raw_bytes()).map_err(|_| PublicationError::Invalid)?;
        for manifest in records.manifests {
            #[derive(Deserialize)]
            struct Locator {
                backup_id: String,
            }
            let value: Locator = serde_json::from_slice(manifest.raw_bytes())
                .map_err(|_| PublicationError::Invalid)?;
            // The sole full decoder and reducer already validated this ID,
            // historical payload and legal pending/ACK transition. They remain
            // required even when the corresponding physical file is gone.
            let id = &value.backup_id;
            super::id(id)?;
            let backups = self.control.child("backups", self.end)?;
            let parent = backups.child(id, self.end)?;
            let suffix = &self.admission.record.update_id["update_".len()..];
            let binding = if id == &format!("transition_catalog_{suffix}") {
                &bindings.preimages.catalog
            } else if id == &format!("transition_control_{suffix}") {
                &bindings.preimages.control
            } else {
                return Err(PublicationError::Invalid);
            };
            binding.matches_parent(&parent)?;
            let actual = parent.read("manifest.json", PROOF_LIMIT, self.end)?;
            if matches!(binding.manifest, ManifestStamp::Absent) {
                // Never infer absence merely from an I/O error, or clear a
                // still-Complete pending slot early. This is only the closed
                // reducer's deletion ACK or its already acknowledged successor.
                ensure(binding.image.deleting_or_deleted() && actual.is_none())?;
                pins.absent_manifests.push(parent);
            } else {
                let actual = actual.ok_or(PublicationError::Changed)?;
                ensure(actual.raw == manifest.raw_bytes())?;
                binding.matches(&parent, &actual)?;
                pins.present.push(Immutable {
                    directory: parent,
                    name: "manifest.json",
                    slot: actual,
                });
            }
        }
        Ok(pins)
    }

    fn proof_files(&self, records: RecordSet<'_>, allow_new: bool) -> Result<Vec<Immutable>> {
        let mut pins = Vec::new();
        for proof in records.proofs {
            let name = proof_key(proof)?.filename();
            match self.run.read(name, PROOF_LIMIT, self.end)? {
                Some(slot) => {
                    ensure(slot.raw == proof.raw_bytes())?;
                    pins.push(Immutable {
                        directory: self
                            .update
                            .child(&self.admission.record.update_id, self.end)?,
                        name,
                        slot,
                    });
                }
                None => ensure(allow_new)?,
            }
        }
        Ok(pins)
    }
}

// Read only these physical fields after full StateV2/record validation. This is
// not an alternate accepted wire model: the reducer remains the sole authority
// for tags, phase/ownership transitions, relations and limits.
#[derive(Deserialize)]
struct ManifestBindings {
    preimages: PreimageBindings,
}

#[derive(Deserialize)]
struct PreimageBindings {
    catalog: ManifestBinding,
    control: ManifestBinding,
}

#[derive(Deserialize)]
struct ManifestBinding {
    parent: ParentBinding,
    image: ImageStatus,
    manifest: ManifestStamp,
}

#[derive(Deserialize)]
struct ImageStatus {
    kind: ImageKind,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImageKind {
    Registered,
    OwnedIncomplete,
    Complete,
    Adopted,
    Reclaimed,
    DeleteIntent,
    Deleted,
    Absent,
}

impl ImageStatus {
    fn deleting_or_deleted(&self) -> bool {
        matches!(
            self.kind,
            ImageKind::DeleteIntent | ImageKind::Deleted | ImageKind::Absent
        )
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ParentBinding {
    AbsentUnderBoundRoot,
    Owned { identity: RecordedIdentity },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ManifestStamp {
    Absent,
    OwnedIncomplete { identity: RecordedIdentity },
    Complete { stamp: RecordedStamp },
}

#[derive(Deserialize)]
struct RecordedStamp {
    identity: RecordedIdentity,
    size_bytes: u64,
    blake3: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RecordedIdentity {
    Unix { device: u64, inode: u64 },
    Windows { volume: u64, file_id: String },
}

impl RecordedIdentity {
    fn matches(&self, native: NativeIdentity) -> Result<()> {
        match self {
            Self::Unix { device, inode } => {
                ensure(cfg!(unix) && native.volume == *device && native.file == u128::from(*inode))
            }
            Self::Windows { volume, file_id } => {
                let raw = native.file.to_le_bytes();
                let mut encoded = String::with_capacity(32);
                for byte in raw {
                    use std::fmt::Write;
                    write!(&mut encoded, "{byte:02x}").map_err(|_| PublicationError::Invalid)?;
                }
                ensure(cfg!(windows) && native.volume == *volume && &encoded == file_id)
            }
        }
    }
}

impl ManifestBinding {
    fn matches_parent(&self, directory: &Directory) -> Result<()> {
        let ParentBinding::Owned { identity } = &self.parent else {
            return Err(PublicationError::Invalid);
        };
        identity.matches(directory.identity)
    }

    fn matches(&self, directory: &Directory, file: &Slot) -> Result<()> {
        self.matches_parent(directory)?;
        match &self.manifest {
            ManifestStamp::Complete { stamp } => {
                stamp.identity.matches(file.identity)?;
                ensure(
                    stamp.size_bytes == file.raw.len() as u64
                        && stamp.blake3 == blake3::hash(&file.raw).to_hex().as_str(),
                )
            }
            ManifestStamp::OwnedIncomplete { identity } => {
                identity.matches(file.identity)?;
                Err(PublicationError::Invalid)
            }
            ManifestStamp::Absent => Err(PublicationError::Invalid),
        }
    }
}

#[derive(Deserialize)]
struct Header {
    seq: u64,
}

impl Header {
    fn read(state: &StateV2) -> Result<Self> {
        // Projection only after the sole closed StateV2 decoder; never another
        // admissible wire shape or a source of successor/phase rules.
        serde_json::from_slice(state.raw_bytes()).map_err(|_| PublicationError::Invalid)
    }
}

fn proof_key(proof: &ProofRecord) -> Result<RecordSlot> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        slot: RecordSlot,
        size_bytes: u64,
        sha256: String,
    }
    let reference: Reference =
        serde_json::from_slice(&proof.reference_bytes()?).map_err(|_| PublicationError::Invalid)?;
    ensure(
        reference.size_bytes == proof.raw_bytes().len() as u64
            && reference.sha256 == sha256(proof.raw_bytes()),
    )?;
    Ok(reference.slot)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    InitialAdmission,
    InitialState,
    InitialGuardReady,
    InitialGuardPublished,
    InitialCandidate,
    InitialActive,
    ProofWritten,
    CandidateWritten,
    RetainedProofFlushed,
    RetainedCandidateFlushed,
    ReceiverCheck,
    CurrentRead,
    #[cfg(test)]
    ActiveDisplaced,
    ProofFlushed,
    CandidateFlushed,
    Exchanged,
    DisplacedStored,
    ReadBack,
}

#[cfg(test)]
thread_local! {
    static FAILURE: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
    static UNWIND: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
}

fn fault(point: Fault) -> Result<()> {
    #[cfg(test)]
    if UNWIND.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            true
        } else {
            false
        }
    }) {
        panic!("injected publication unwind");
    }
    #[cfg(test)]
    if FAILURE.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(PublicationError::Io);
    }
    #[cfg(not(test))]
    let _ = point;
    Ok(())
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        ptr,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, IsValidSid,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        },
    };

    pub(super) fn directory(parent: &Directory, name: &str) -> io::Result<File> {
        platform::directory(&parent.path.join(name))
    }
    fn options(parent: &Directory, name: &str, write: bool, create: bool) -> io::Result<File> {
        fs::OpenOptions::new()
            .read(true)
            .write(write)
            .create_new(create)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(parent.path.join(name))
    }
    pub(super) fn read(parent: &Directory, name: &str) -> io::Result<File> {
        options(parent, name, false, false)
    }
    pub(super) fn writable(parent: &Directory, name: &str) -> io::Result<File> {
        options(parent, name, true, false)
    }
    pub(super) fn create(parent: &Directory, name: &str) -> io::Result<File> {
        options(parent, name, true, true)
    }
    pub(super) fn metadata_pin(parent: &Directory, name: &str) -> io::Result<File> {
        // access_mode(0) overrides data access; no create flags means
        // OPEN_EXISTING. Rust's OpenOptions uses a non-inheritable handle.
        let file = fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(parent.path.join(name))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(file)
    }
    struct Security {
        descriptor: PSECURITY_DESCRIPTOR,
        owner: PSID,
        acl: *mut ACL,
    }
    impl Drop for Security {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocated this single descriptor; the
            // owner and ACL pointers are borrowed views into the allocation.
            unsafe {
                LocalFree(self.descriptor);
            }
        }
    }
    fn security(file: &File) -> io::Result<Security> {
        let mut result = Security {
            descriptor: ptr::null_mut(),
            owner: ptr::null_mut(),
            acl: ptr::null_mut(),
        };
        // SAFETY: live non-owning file handle, writable pointer outputs, no
        // callback. The successful allocation is retained by result's Drop.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut result.owner,
                ptr::null_mut(),
                &mut result.acl,
                ptr::null_mut(),
                &mut result.descriptor,
            )
        };
        if status != 0 || result.owner.is_null() || result.acl.is_null() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(result)
    }
    pub(super) fn private_file(parent: &Directory, file: &File) -> io::Result<()> {
        let meta = file.metadata()?;
        if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the live borrowed handle and exact sized output remain valid.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.nNumberOfLinks != 1
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let parent_security = security(&parent.file)?;
        let actual = security(file)?;
        // Parent was checked against the application's exact private-directory
        // DACL. A file may inherit it, but may not add another principal or be
        // replaced with an externally writable hardlink.
        if unsafe { EqualSid(actual.owner, parent_security.owner) } == 0
            || unsafe { (*actual.acl).AceCount } != 1
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut ace = ptr::null_mut();
        // SAFETY: ACL belongs to the live descriptor, GetAce bounds-checks the
        // index. The header and SID offsets are checked before interpreting it.
        if unsafe { GetAce(actual.acl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if header.AceType != 0
            || header.AceFlags & 8 != 0
            || usize::from(header.AceSize) < sid_offset + 8
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        // A native SID is an 8-byte header plus four bytes per subauthority.
        // Validate its whole extent before calling any SID-reading function.
        let subauthorities = usize::from(unsafe { *ace.cast::<u8>().add(sid_offset + 1) });
        if subauthorities > 15 || 8 + 4 * subauthorities > usize::from(header.AceSize) - sid_offset
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if allowed.Mask != FILE_ALL_ACCESS
            || unsafe { IsValidSid(sid) } == 0
            || unsafe { GetLengthSid(sid) } as usize > usize::from(header.AceSize) - sid_offset
            || unsafe { EqualSid(sid, actual.owner) } == 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    pub(super) fn sync(_: &Directory) -> io::Result<()> {
        // Match the existing platform boundary: Windows has no general
        // unprivileged directory fsync. File FlushFileBuffers is checked above.
        Ok(())
    }
    pub(super) fn move_new(
        from: &Directory,
        source: &str,
        to: &Directory,
        target: &str,
    ) -> io::Result<()> {
        platform::move_new(&from.path.join(source), &to.path.join(target))
    }
    pub(super) fn replace(
        active: &Directory,
        target: &str,
        run: &Directory,
        candidate: &str,
        displaced: &str,
    ) -> io::Result<()> {
        platform::replace(
            &active.path.join(target),
            &run.path.join(candidate),
            &run.path.join(displaced),
        )
    }
    pub(super) fn remove(parent: &Directory, name: &str) -> io::Result<()> {
        fs::remove_file(parent.path.join(name))
    }
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::{
        ffi::CString,
        os::unix::{
            fs::MetadataExt,
            io::{AsRawFd, FromRawFd},
        },
    };

    fn name(value: &str) -> io::Result<CString> {
        if value.is_empty() || value == "." || value == ".." || value.contains('/') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        CString::new(value).map_err(|_| io::ErrorKind::InvalidInput.into())
    }
    fn open(parent: &Directory, child: &str, flags: i32) -> io::Result<File> {
        let child = name(child)?;
        // SAFETY: parent retains its directory descriptor. child is one NUL
        // terminated basename; a successful fresh descriptor is owned by File.
        let fd = unsafe {
            libc::openat(
                parent.file.as_raw_fd(),
                child.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    pub(super) fn directory(parent: &Directory, child: &str) -> io::Result<File> {
        open(parent, child, libc::O_RDONLY | libc::O_DIRECTORY)
    }
    pub(super) fn read(parent: &Directory, child: &str) -> io::Result<File> {
        open(parent, child, libc::O_RDONLY)
    }
    pub(super) fn writable(parent: &Directory, child: &str) -> io::Result<File> {
        open(parent, child, libc::O_RDWR)
    }
    pub(super) fn create(parent: &Directory, child: &str) -> io::Result<File> {
        open(parent, child, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)
    }
    pub(super) fn private_file(_: &Directory, file: &File) -> io::Result<()> {
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    pub(super) fn sync(parent: &Directory) -> io::Result<()> {
        parent.file.sync_all()
    }
    fn rename(
        from: &Directory,
        source: &str,
        to: &Directory,
        target: &str,
        exchange: bool,
    ) -> io::Result<()> {
        let source = name(source)?;
        let target = name(target)?;
        // SAFETY: both directory descriptors and both basename C strings remain
        // live through the syscall. Unsupported atomic semantics never fall back.
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                from.file.as_raw_fd(),
                source.as_ptr(),
                to.file.as_raw_fd(),
                target.as_ptr(),
                if exchange {
                    libc::RENAME_EXCHANGE
                } else {
                    libc::RENAME_NOREPLACE
                },
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                from.file.as_raw_fd(),
                source.as_ptr(),
                to.file.as_raw_fd(),
                target.as_ptr(),
                if exchange {
                    libc::RENAME_SWAP
                } else {
                    libc::RENAME_EXCL
                },
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = -1;
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    pub(super) fn move_new(
        from: &Directory,
        source: &str,
        to: &Directory,
        target: &str,
    ) -> io::Result<()> {
        rename(from, source, to, target, false)
    }
    pub(super) fn replace(
        active: &Directory,
        target: &str,
        run: &Directory,
        candidate: &str,
        _: &str,
    ) -> io::Result<()> {
        rename(active, target, run, candidate, true)
    }
    pub(super) fn remove(parent: &Directory, child: &str) -> io::Result<()> {
        let child = name(child)?;
        // SAFETY: unlink only the checked basename under the retained parent.
        if unsafe { libc::unlinkat(parent.file.as_raw_fd(), child.as_ptr(), 0) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "update_schema_transition_runtime_tests.rs"]
mod tests;
