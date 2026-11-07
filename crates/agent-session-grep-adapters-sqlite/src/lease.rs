//! Data-root writer lease：每个 data root 同时只允许一个写者。
//!
//! 权威是 OS 独占文件句柄，不是 PID 超时抢锁。进程崩溃后 OS 自动释放。
//! Windows 上 fs4 独占锁是强制锁：持锁期间不得对同一路径另开句柄读写
//! （os error 33）——所有 lease record 读写必须复用同一持锁句柄。
//!
//! 同进程二次 `try_acquire`：Windows 上 open/try_lock 有时仍成功，但写 record
//! 时才 error 33。因此用进程内路径集合作快速拒绝，并把写阶段的锁错误也归一
//! 为 "lease held"。
//!
//! 证据：`spikes/data-root-locking/EVIDENCE.md`。

use agent_session_grep_ports::{PortError, PortResult};
use fs4::fs_std::FileExt;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

fn backend<E: std::fmt::Display>(e: E) -> PortError {
    PortError::Backend(e.to_string())
}

fn held_error() -> PortError {
    PortError::WriterBusy("writer lease is already held".into())
}

/// Windows 强制锁下，持锁时对同一路径再 open/写会报 error 33 / 32。
fn is_lock_contention(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        // Windows ERROR_SHARING_VIOLATION=32, ERROR_LOCK_VIOLATION=33。
        Some(32) | Some(33) => true,
        _ => matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

fn lock_exclusive(file: &File) -> PortResult<()> {
    classify_lock_result(file.try_lock_exclusive())
}

fn classify_lock_result(result: std::io::Result<bool>) -> PortResult<()> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(held_error()),
        Err(e) if is_lock_contention(&e) => Err(held_error()),
        Err(e) => Err(backend(e)),
    }
}

/// 本进程内已持有的 lock 路径（规范化字符串）。
///
/// OS 锁在跨进程时是权威；同进程二次抢锁在 Windows 上行为不一致
/// （open 可能成功、写才失败），用此集合作确定性拒绝。
fn held_paths() -> &'static Mutex<HashSet<String>> {
    static HELD: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(HashSet::new()))
}

fn path_key(path: &Path) -> String {
    // 尽量规范化，避免 `dir/writer.lock` 与 `dir\writer.lock` 被视为两个。
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

/// 对 data-root 的独占 writer lease。
///
/// 持有本结构即持有锁；`Drop` 时释放 OS 锁并注销进程内登记。
/// 不要在持锁期间对 `path` 另开句柄——Windows 会 error 33。
#[derive(Debug)]
pub struct WriterLease {
    path: PathBuf,
    key: String,
    file: Option<File>,
    // Transition admission retains this actual parent through file and claim
    // release; ordinary writer acquisition preserves its existing behavior.
    transition_root: Option<crate::managed_locks::TransitionWriterRoot>,
}

impl WriterLease {
    /// 尝试在 `data_root/writer.lock` 上获取独占 lease。
    ///
    /// 已被本进程或其他进程持有时立即返回 [`PortError::WriterBusy`]（不阻塞）。
    pub fn try_acquire(data_root: &Path) -> PortResult<Self> {
        std::fs::create_dir_all(data_root).map_err(backend)?;
        let path = data_root.join("writer.lock");
        let key = path_key(&path);

        // 进程内先登记（claim）再碰 OS 锁：OS 锁获取与 held-set 登记之间的窗口
        // 会让两个并发线程双双通过预检查（Unix 同进程锁语义下 OS 层未必互斥），
        // 造成双持。登记先于任何等待点完成，后续任何失败路径回滚登记。
        {
            let mut held = held_paths()
                .lock()
                .map_err(|e| backend(format!("lease registry poisoned: {e}")))?;
            if held.iter().any(|k| paths_same_dir(k, &path)) || held.contains(&key) {
                return Err(held_error());
            }
            held.insert(key.clone());
        }

        let mut file = match OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if is_lock_contention(&e) => {
                remove_claim(&key);
                return Err(held_error());
            }
            Err(e) => {
                remove_claim(&key);
                return Err(backend(e));
            }
        };

        if let Err(e) = lock_exclusive(&file) {
            remove_claim(&key);
            return Err(e);
        }

        // 写诊断 record；Windows 同进程第二句柄写会 error 33——归一为 held。
        let record = format!(
            "pid={}\nprocess_start_unix_ms={}\nfencing_token={}\n",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            (std::process::id() as u64) << 32
                | (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    & 0xffff_ffff),
        );
        if let Err(e) = write_record(&mut file, &record) {
            let _ = FileExt::unlock(&file);
            remove_claim(&key);
            if is_lock_contention(&e) {
                return Err(held_error());
            }
            return Err(backend(e));
        }

        Ok(WriterLease {
            path,
            key,
            file: Some(file),
            transition_root: None,
        })
    }

    /// Acquire only the already-existing writer for an exact transition root.
    /// No directory, lock file, diagnostic record or repair is created here.
    pub fn try_acquire_for_transition(
        data_root: &Path,
        expected: crate::managed_locks::RootIdentity,
    ) -> PortResult<Self> {
        let root = crate::managed_locks::TransitionWriterRoot::open(data_root, expected)?;
        let path = data_root.join("writer.lock");
        let key = path_key(&path);
        {
            let mut held = held_paths()
                .lock()
                .map_err(|_| PortError::Backend("writer lease registry unavailable".into()))?;
            if held.iter().any(|k| paths_same_dir(k, &path)) || held.contains(&key) {
                return Err(held_error());
            }
            held.insert(key.clone());
        }
        // Install cleanup before opening/locking so error and unwind follow
        // the same file-before-claim-before-root release order as success.
        let mut lease = Self {
            path,
            key,
            file: None,
            transition_root: Some(root),
        };
        let file = lease.transition_root.as_ref().unwrap().open_writer()?;
        lease.file = Some(file);
        lock_exclusive(lease.file())?;
        #[cfg(test)]
        tests::after_transition_lock();
        lease.validate_current(data_root)?;
        Ok(lease)
    }

    fn file(&self) -> &File {
        self.file.as_ref().expect("writer lease has an owned file")
    }

    /// lease 文件路径（诊断用）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify this retained writer handle still owns the current named file.
    /// This neither acquires a lock nor reads/writes diagnostic contents.
    /// A composite capability must also validate its pinned physical data root.
    pub fn validate_current(&self, root: &Path) -> PortResult<()> {
        if self.path != root.join("writer.lock") {
            return Err(PortError::SourceIo("writer lease binding changed".into()));
        }
        if let Some(pinned) = &self.transition_root {
            pinned.validate(root, self.file())
        } else {
            crate::managed_locks::validate_writer_file(root, self.file())
        }
    }

    /// Verify a caller's already opened proof file is this retained locked file.
    /// Only metadata is inspected; neither handle is locked, read or exposed.
    /// Callers must also validate the current name and pinned physical root.
    pub fn validate_proof_file(&self, candidate: &File) -> PortResult<()> {
        crate::managed_locks::validate_writer_handle(self.file(), candidate)
    }

    /// 读回本进程写入的 lease record（同一持锁句柄，避免 Windows error 33）。
    pub fn read_record(&mut self) -> PortResult<String> {
        let file = self.file.as_mut().expect("writer lease has an owned file");
        file.seek(SeekFrom::Start(0)).map_err(backend)?;
        let mut buf = String::new();
        file.read_to_string(&mut buf).map_err(backend)?;
        Ok(buf)
    }
}

fn write_record(file: &mut File, record: &str) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(record.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// 回滚 [`WriterLease::try_acquire`] 早期的进程内登记。任何失败路径都必须调用，
/// 否则本进程会永久拒绝该 data root。
fn remove_claim(key: &str) {
    held_paths()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(key);
}

/// 粗略判断两个 lock 路径是否指向同一目录下的 writer.lock（canonicalize 失败时的后备）。
fn paths_same_dir(held_key: &str, candidate: &Path) -> bool {
    let held = Path::new(held_key);
    match (held.parent(), candidate.parent()) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = FileExt::unlock(&file);
            drop(file);
        }
        remove_claim(&self.key);
        // transition_root remains live until after this Drop body.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static AFTER_TRANSITION_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn after_transition_lock() {
        let hook = AFTER_TRANSITION_LOCK.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    #[test]
    fn acquire_and_read_record() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let mut lease = WriterLease::try_acquire(dir.path()).unwrap();
        let rec = lease.read_record().unwrap();
        assert!(rec.contains("pid="), "record={rec}");
        assert!(rec.contains("fencing_token="), "record={rec}");
    }

    #[test]
    fn transition_writer_requires_existing_root_and_preserves_record_and_os_lock() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let expected = crate::managed_locks::RootIdentity::read(root.path()).unwrap();
        let missing_root = root.path().join("not-created");
        assert!(WriterLease::try_acquire_for_transition(&missing_root, expected).is_err());
        assert!(!missing_root.exists());
        assert!(WriterLease::try_acquire_for_transition(root.path(), expected).is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        let original = {
            let mut ordinary = WriterLease::try_acquire(root.path()).unwrap();
            assert!(matches!(
                WriterLease::try_acquire_for_transition(root.path(), expected),
                Err(PortError::WriterBusy(_))
            ));
            ordinary.read_record().unwrap()
        };
        let mut lease = WriterLease::try_acquire_for_transition(root.path(), expected).unwrap();
        assert_eq!(lease.read_record().unwrap(), original);
        assert!(matches!(
            WriterLease::try_acquire(root.path()),
            Err(PortError::WriterBusy(_))
        ));
        assert!(matches!(
            WriterLease::try_acquire_for_transition(root.path(), expected),
            Err(PortError::WriterBusy(_))
        ));
        let mut contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lease.path())
            .unwrap();
        for _ in 0..3 {
            lease.validate_current(root.path()).unwrap();
            assert!(matches!(
                lock_exclusive(&contender),
                Err(PortError::WriterBusy(_))
            ));
            assert_eq!(lease.read_record().unwrap(), original);
        }
        drop(lease);
        lock_exclusive(&contender).unwrap();
        contender.seek(SeekFrom::Start(0)).unwrap();
        let mut after = String::new();
        contender.read_to_string(&mut after).unwrap();
        assert_eq!(after, original);
        FileExt::unlock(&contender).unwrap();
        drop(contender);
        assert_eq!(
            std::fs::read_to_string(root.path().join("writer.lock")).unwrap(),
            original
        );
    }

    #[test]
    fn transition_writer_rejects_wrong_root_links_and_releases_failed_claims() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let other = agent_session_grep_testkit::tempdir().unwrap();
        let expected = crate::managed_locks::RootIdentity::read(root.path()).unwrap();
        let foreign = crate::managed_locks::RootIdentity::read(other.path()).unwrap();
        let path = root.path().join("writer.lock");
        std::fs::write(&path, b"retained writer diagnostics").unwrap();
        assert!(WriterLease::try_acquire_for_transition(root.path(), foreign).is_err());
        let alias = root.path().join("writer-alias");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(WriterLease::try_acquire_for_transition(root.path(), expected).is_err());
        assert!(alias.exists());
        std::fs::remove_file(&alias).unwrap();
        let mut blocker = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        lock_exclusive(&blocker).unwrap();
        assert!(matches!(
            WriterLease::try_acquire_for_transition(root.path(), expected),
            Err(PortError::WriterBusy(_))
        ));
        blocker.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = String::new();
        blocker.read_to_string(&mut bytes).unwrap();
        assert_eq!(bytes, "retained writer diagnostics");
        FileExt::unlock(&blocker).unwrap();
        drop(blocker);
        AFTER_TRANSITION_LOCK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(|| {
                panic!("synthetic partial transition writer unwind");
            }));
        });
        assert!(
            std::panic::catch_unwind(|| {
                let _lease = WriterLease::try_acquire_for_transition(root.path(), expected);
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                let _lease =
                    WriterLease::try_acquire_for_transition(root.path(), expected).unwrap();
                panic!("synthetic held transition writer unwind");
            })
            .is_err()
        );
        let lease = WriterLease::try_acquire_for_transition(root.path(), expected).unwrap();
        assert!(lease.validate_current(other.path()).is_err());
        lease.validate_current(root.path()).unwrap();
        drop(lease);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"retained writer diagnostics"
        );
    }

    #[cfg(unix)]
    #[test]
    fn transition_writer_rejects_symlinks_and_retained_root_replacement() {
        use std::os::unix::fs::symlink;
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("data");
        std::fs::create_dir(&root).unwrap();
        let expected = crate::managed_locks::RootIdentity::read(&root).unwrap();
        let actual = temp.path().join("actual-writer");
        std::fs::write(&actual, b"original").unwrap();
        symlink(&actual, root.join("writer.lock")).unwrap();
        assert!(WriterLease::try_acquire_for_transition(&root, expected).is_err());
        assert_eq!(std::fs::read(&actual).unwrap(), b"original");
        std::fs::remove_file(root.join("writer.lock")).unwrap();
        std::fs::write(root.join("writer.lock"), b"retained").unwrap();
        let mut lease = WriterLease::try_acquire_for_transition(&root, expected).unwrap();
        let moved = temp.path().join("original-data");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("writer.lock"), b"retained").unwrap();
        assert!(lease.validate_current(&root).is_err());
        assert_eq!(lease.read_record().unwrap(), "retained");
        assert_eq!(
            std::fs::read(root.join("writer.lock")).unwrap(),
            b"retained"
        );
    }

    #[cfg(unix)]
    #[test]
    fn transition_writer_post_lock_replacement_rejects_and_releases_old_file() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let expected = crate::managed_locks::RootIdentity::read(&root).unwrap();
        let path = root.join("writer.lock");
        let old = root.join("previous-writer");
        std::fs::write(&path, b"retained diagnostics").unwrap();
        AFTER_TRANSITION_LOCK.with(|slot| {
            let path = path.clone();
            let old = old.clone();
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&path, &old).unwrap();
                std::fs::write(&path, b"retained diagnostics").unwrap();
            }));
        });
        assert!(WriterLease::try_acquire_for_transition(&root, expected).is_err());
        let original = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&old)
            .unwrap();
        lock_exclusive(&original).unwrap();
        FileExt::unlock(&original).unwrap();
        drop(WriterLease::try_acquire_for_transition(&root, expected).unwrap());
        assert_eq!(std::fs::read(&old).unwrap(), b"retained diagnostics");
        assert_eq!(std::fs::read(&path).unwrap(), b"retained diagnostics");
    }

    #[test]
    fn held_writer_validation_preserves_nonempty_diagnostics_and_os_lock() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let other = agent_session_grep_testkit::tempdir().unwrap();
        let mut lease = WriterLease::try_acquire(root.path()).unwrap();
        let before = lease.read_record().unwrap();
        assert!(!before.is_empty());
        // Bypass the in-process path registry: validation must not release the
        // actual OS lock when its independently opened metadata handle closes.
        let mut contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lease.path())
            .unwrap();
        for _ in 0..3 {
            lease.validate_current(root.path()).unwrap();
            lease.validate_proof_file(&contender).unwrap();
            assert!(matches!(
                lock_exclusive(&contender),
                Err(PortError::WriterBusy(_))
            ));
            assert_eq!(lease.read_record().unwrap(), before);
        }
        assert!(lease.validate_current(other.path()).is_err());
        assert_eq!(std::fs::read_dir(other.path()).unwrap().count(), 0);
        let unrelated_path = other.path().join("proof-candidate");
        std::fs::write(&unrelated_path, &before).unwrap();
        let unrelated = File::open(&unrelated_path).unwrap();
        assert!(lease.validate_proof_file(&unrelated).is_err());
        assert_eq!(lease.read_record().unwrap(), before);
        drop(lease);
        lock_exclusive(&contender).unwrap();
        contender.seek(SeekFrom::Start(0)).unwrap();
        let mut after = String::new();
        contender.read_to_string(&mut after).unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn held_writer_validation_rejects_same_bytes_on_a_different_inode() {
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let mut lease = WriterLease::try_acquire(root.path()).unwrap();
        let before = lease.read_record().unwrap();
        let path = root.path().join("writer.lock");
        let old = root.path().join("original-writer");
        match std::fs::rename(&path, &old) {
            Ok(()) => {}
            #[cfg(windows)]
            Err(error) => {
                // Some Windows filesystems deny replacement of the locked
                // image. Assert that protection instead of claiming injection.
                assert!(matches!(error.raw_os_error(), Some(5 | 32 | 33)));
                lease.validate_current(root.path()).unwrap();
                assert_eq!(lease.read_record().unwrap(), before);
                return;
            }
            #[cfg(not(windows))]
            Err(error) => panic!("{error}"),
        }
        assert!(lease.validate_current(root.path()).is_err());
        assert!(!path.exists());
        std::fs::write(&path, &before).unwrap();
        assert!(lease.validate_current(root.path()).is_err());
        assert_eq!(lease.read_record().unwrap(), before);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(lease.validate_current(root.path()).is_err());
        assert!(path.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn held_writer_validation_rejects_symlink_and_hardlink_without_repair() {
        use std::os::unix::fs::symlink;
        let root = agent_session_grep_testkit::tempdir().unwrap();
        let mut lease = WriterLease::try_acquire(root.path()).unwrap();
        let before = lease.read_record().unwrap();
        let path = root.path().join("writer.lock");
        let old = root.path().join("original-writer");
        std::fs::rename(&path, &old).unwrap();
        symlink(&old, &path).unwrap();
        assert!(lease.validate_current(root.path()).is_err());
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&old, &path).unwrap();
        assert!(lease.validate_current(root.path()).is_err());
        assert_eq!(lease.read_record().unwrap(), before);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn true_lock_result_is_acquired() {
        assert!(classify_lock_result(Ok(true)).is_ok());
    }

    #[test]
    fn false_lock_result_is_writer_busy() {
        let err = classify_lock_result(Ok(false)).unwrap_err();
        assert!(matches!(err, PortError::WriterBusy(_)), "got {err:?}");
    }

    #[test]
    fn contention_lock_error_is_writer_busy() {
        let io_error = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        let err = classify_lock_result(Err(io_error)).unwrap_err();
        assert!(matches!(err, PortError::WriterBusy(_)), "got {err:?}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_sharing_and_lock_violations_are_writer_busy() {
        for code in [32, 33] {
            let err =
                classify_lock_result(Err(std::io::Error::from_raw_os_error(code))).unwrap_err();
            assert!(
                matches!(err, PortError::WriterBusy(_)),
                "code={code}, got {err:?}"
            );
        }
    }

    #[test]
    fn non_contention_lock_error_is_backend() {
        let io_error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let err = classify_lock_result(Err(io_error)).unwrap_err();
        assert!(matches!(err, PortError::Backend(_)), "got {err:?}");
    }

    #[test]
    fn second_acquire_is_denied_without_disclosing_path() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let _holder = WriterLease::try_acquire(dir.path()).unwrap();
        let err = WriterLease::try_acquire(dir.path()).unwrap_err();
        let message = match err {
            PortError::WriterBusy(message) => message,
            other => panic!("got {other:?}"),
        };
        assert!(message.contains("writer lease"), "message={message}");
        assert!(
            !message.contains(&dir.path().display().to_string()),
            "message disclosed data root: {message}"
        );
        assert!(
            !message.contains("writer.lock"),
            "message disclosed lock filename: {message}"
        );
    }

    #[test]
    fn drop_releases_for_next_holder() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        {
            let _holder = WriterLease::try_acquire(dir.path()).unwrap();
        }
        // Drop 后应能立即重获。
        let again = WriterLease::try_acquire(dir.path());
        assert!(again.is_ok(), "after drop: {again:?}");
    }
}
