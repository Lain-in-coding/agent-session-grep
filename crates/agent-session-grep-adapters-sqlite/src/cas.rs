//! CAS activation：仅当 `CURRENT == expected_base` 时切换 generation。
//!
//! 证据：`spikes/data-root-locking` assertion C。生产路径应在持有
//! [`crate::WriterLease`] 下调用，本模块只负责比较-交换语义本身。

use agent_session_grep_ports::{PortError, PortResult};
use std::path::Path;

fn backend<E: std::fmt::Display>(e: E) -> PortError {
    PortError::Backend(e.to_string())
}

/// 读 data-root 下 `CURRENT` 文件中的 generation 号。
///
/// 文件不存在时视为 generation 0（尚未激活任何 generation）。
pub fn read_current(data_root: &Path) -> PortResult<u64> {
    let path = data_root.join("CURRENT");
    match std::fs::read_to_string(&path) {
        Ok(s) => s
            .trim()
            .parse()
            .map_err(|e| backend(format!("CURRENT parse failed: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(backend(e)),
    }
}

/// 无条件写 `CURRENT`（仅测试/初始化用；生产激活走 [`cas_activate`]）。
pub fn write_current(data_root: &Path, generation: u64) -> PortResult<()> {
    std::fs::create_dir_all(data_root).map_err(backend)?;
    let path = data_root.join("CURRENT");
    write_synced(&path, generation.to_string().as_bytes())
}

/// 写文件并 `sync_all`：CURRENT 是激活 CAS 的权威指针，必须先落盘再让后续
/// 读取看到新值，否则崩溃后可能读到半写的旧内容。
fn write_synced(path: &Path, bytes: &[u8]) -> PortResult<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(backend)?;
    file.write_all(bytes).map_err(backend)?;
    file.sync_all().map_err(backend)?;
    Ok(())
}

/// CAS：仅当 `CURRENT == expected` 时切换到 `new`，返回是否成功切换。
///
/// 实现：读 CURRENT → 相等则写临时文件再 `rename` 覆盖（Windows 上 rename
/// 到已存在目标是替换语义）。过期基线返回 `Ok(false)`，不修改 CURRENT。
pub fn cas_activate(data_root: &Path, expected: u64, new: u64) -> PortResult<bool> {
    std::fs::create_dir_all(data_root).map_err(backend)?;
    let current = data_root.join("CURRENT");
    let cur = match std::fs::read_to_string(&current) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|e| backend(format!("CURRENT parse failed: {e}")))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(backend(e)),
    };
    if cur != expected {
        return Ok(false);
    }
    // tmp 名带 pid，避免同进程并发激活互相踩踏（生产路径持 WriterLease，单写者，
    // 但防御性唯一化成本为零）。临时文件同样 sync 后 rename，保证激活可观测。
    let tmp = current.with_extension(format!("tmp.{}", std::process::id()));
    write_synced(&tmp, new.to_string().as_bytes())?;
    std::fs::rename(&tmp, &current).map_err(backend)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_current_reads_as_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_current(dir.path()).unwrap(), 0);
    }

    #[test]
    fn cas_succeeds_when_expected_matches() {
        let dir = tempfile::tempdir().unwrap();
        write_current(dir.path(), 17).unwrap();
        assert!(cas_activate(dir.path(), 17, 18).unwrap());
        assert_eq!(read_current(dir.path()).unwrap(), 18);
    }

    #[test]
    fn cas_rejects_stale_baseline() {
        let dir = tempfile::tempdir().unwrap();
        write_current(dir.path(), 17).unwrap();
        assert!(cas_activate(dir.path(), 17, 18).unwrap());
        // 过期基线 17，CURRENT 已是 18 → 拒，CURRENT 保持 18。
        assert!(!cas_activate(dir.path(), 17, 99).unwrap());
        assert_eq!(read_current(dir.path()).unwrap(), 18);
    }

    #[test]
    fn cas_from_zero_bootstraps() {
        let dir = tempfile::tempdir().unwrap();
        assert!(cas_activate(dir.path(), 0, 1).unwrap());
        assert_eq!(read_current(dir.path()).unwrap(), 1);
    }

    #[test]
    fn cas_activate_leaves_no_tmp_files_behind() {
        // 回归（Minor-13）：临时文件带 pid 唯一后缀且成功 rename 后必须不残留
        // （崩溃遗留的旧 tmp 会被下次 write 截断复用）。
        let dir = tempfile::tempdir().unwrap();
        write_current(dir.path(), 17).unwrap();
        assert!(cas_activate(dir.path(), 17, 18).unwrap());
        assert_eq!(read_current(dir.path()).unwrap(), 18);
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "tmp files left behind: {leftovers:?}");
    }
}
