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
    file: File,
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

        Ok(WriterLease { path, key, file })
    }

    /// lease 文件路径（诊断用）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读回本进程写入的 lease record（同一持锁句柄，避免 Windows error 33）。
    pub fn read_record(&mut self) -> PortResult<String> {
        self.file.seek(SeekFrom::Start(0)).map_err(backend)?;
        let mut buf = String::new();
        self.file.read_to_string(&mut buf).map_err(backend)?;
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
    if let Ok(mut held) = held_paths().lock() {
        held.remove(key);
    }
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
        let _ = FileExt::unlock(&self.file);
        if let Ok(mut held) = held_paths().lock() {
            held.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_read_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut lease = WriterLease::try_acquire(dir.path()).unwrap();
        let rec = lease.read_record().unwrap();
        assert!(rec.contains("pid="), "record={rec}");
        assert!(rec.contains("fencing_token="), "record={rec}");
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
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        {
            let _holder = WriterLease::try_acquire(dir.path()).unwrap();
        }
        // Drop 后应能立即重获。
        let again = WriterLease::try_acquire(dir.path());
        assert!(again.is_ok(), "after drop: {again:?}");
    }
}
