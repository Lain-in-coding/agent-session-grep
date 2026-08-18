//! data-root-locking spike（可丢弃探针，不进 crates/）。
//!
//! 目的：为 data-root 级全局 writer lease 与 CAS activation 提供 Windows 实测证据；
//! 历史来源为 Plan 审查阻断项 #5 与 §6.5。
//!
//! 验证四个断言：
//!   A. 独占 lease：持有者持锁期间，第二个进程 try-lock 立即失败（不是两个进程都拿到）；
//!   B. stale-lock 自愈：持锁进程被杀后，OS 自动释放，新进程能拿到锁（不需要手动清 stale 文件）；
//!   C. CAS activation：CURRENT 指针只有在等于 expected_base 时才切换，防止旧基线覆盖新结果；
//!   D. lease record 诊断：锁文件里写入 owner/pid/process_start/operation_id 供 doctor 读取。
//!
//! 用法：
//!   cargo run --release                 # 主流程，会 spawn 子进程做竞争
//!   cargo run --release -- hold <lock> <ms>   # 内部：持锁 N 毫秒（供 A）
//!   cargo run --release -- try  <lock>        # 内部：尝试拿锁，打印结果（供 A/B）

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use fs4::fs_std::FileExt;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // 内部子命令（被主流程 spawn）
    if args.len() >= 3 && args[1] == "hold" {
        let lock = PathBuf::from(&args[2]);
        let ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1500);
        return child_hold(&lock, ms);
    }
    if args.len() >= 3 && args[1] == "try" {
        let lock = PathBuf::from(&args[2]);
        return child_try(&lock);
    }

    // 主流程
    println!("=== data-root-locking spike ===");
    println!(
        "  os/arch = {}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!();

    let tmp = tempfile::tempdir()?;
    let base = tmp.path();

    eprintln!("[run] A ...");
    let a = assertion_a_exclusive_lease(base)?;
    eprintln!("[run] B ...");
    let b = assertion_b_stale_lock_self_heals(base)?;
    eprintln!("[run] C ...");
    let c = assertion_c_cas_activation(base)?;
    eprintln!("[run] D ...");
    let d = assertion_d_lease_record(base)?;

    println!("\n=== 结论汇总 ===");
    print_result("A 独占 lease：第二进程被拒", a.0, &a.1);
    print_result("B stale-lock 自愈：杀进程后可重获", b.0, &b.1);
    print_result("C CAS activation：旧基线切换被拒", c.0, &c.1);
    print_result("D lease record 诊断字段可读", d.0, &d.1);

    println!("\nContract / decision evidence：");
    println!(
        "  writer lease：Windows 探针支持 OS 独占句柄 + 崩溃释放；正式规范仍需定义其他平台语义；"
    );
    println!(
        "  CAS activation：CURRENT==expected_base 可阻止旧基线覆盖更新结果，正式实现需在 lease 下执行。"
    );

    Ok(())
}

fn print_result(name: &str, pass: bool, detail: &str) {
    println!(
        "  [{}] {name} — {detail}",
        if pass { "PASS" } else { "FAIL" }
    );
}

fn self_exe() -> Result<PathBuf> {
    std::env::current_exe().context("current_exe")
}

// ---- 子进程实现 ----

/// 统一封装 fs4 0.13 的 try_lock_exclusive（返回 Result<bool, io::Error>）：
/// Ok(true) 表示拿到锁，Ok(false) 表示锁被占用。
fn try_lock(file: &File) -> bool {
    matches!(file.try_lock_exclusive(), Ok(true))
}

/// 持锁 ms 毫秒。成功拿到锁则打印 HELD 并保持，到点释放。
fn child_hold(lock_path: &Path, ms: u64) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)?;
    if try_lock(&file) {
        println!("HELD");
        std::io::stdout().flush().ok();
        std::thread::sleep(Duration::from_millis(ms));
        FileExt::unlock(&file).ok();
    } else {
        println!("DENIED");
    }
    Ok(())
}

/// 尝试拿锁：打印 ACQUIRED 或 DENIED，立即释放。
fn child_try(lock_path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)?;
    if try_lock(&file) {
        println!("ACQUIRED");
        FileExt::unlock(&file).ok();
    } else {
        println!("DENIED");
    }
    std::io::stdout().flush().ok();
    Ok(())
}

// ---- 断言 ----

/// A：主进程 spawn 一个持锁 1.5s 的子进程，等它打印 HELD 后，
///    再 spawn 一个 try 子进程，应打印 DENIED。
fn assertion_a_exclusive_lease(base: &Path) -> Result<(bool, String)> {
    let lock = base.join("writer.lock");
    let exe = self_exe()?;

    let mut holder = Command::new(&exe)
        .args(["hold", lock.to_str().unwrap(), "2000"])
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    // 等 holder 打印 HELD
    wait_for_line(holder.stdout.as_mut().unwrap(), "HELD")?;

    // 现在 holder 持锁，try 子进程应被拒
    let out = Command::new(&exe)
        .args(["try", lock.to_str().unwrap()])
        .output()?;
    let contender = String::from_utf8_lossy(&out.stdout);
    let denied = contender.contains("DENIED");

    holder.wait().ok();
    Ok((
        denied,
        format!("holder 持锁时竞争者输出={}（应 DENIED）", contender.trim()),
    ))
}

/// B：spawn 一个持锁子进程，等它 HELD 后直接 kill；随后主进程应能立即拿到锁。
fn assertion_b_stale_lock_self_heals(base: &Path) -> Result<(bool, String)> {
    let lock = base.join("stale.lock");
    let exe = self_exe()?;

    let mut holder = Command::new(&exe)
        .args(["hold", lock.to_str().unwrap(), "60000"]) // 长时间持锁
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    wait_for_line(holder.stdout.as_mut().unwrap(), "HELD")?;

    // 强杀持锁进程（不给它机会 unlock）
    holder.kill().ok();
    holder.wait().ok();

    // 给 OS 一点时间回收句柄
    std::thread::sleep(Duration::from_millis(200));

    // 主进程尝试拿锁——OS 应已释放 stale 锁
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock)?;
    let got = matches!(file.try_lock_exclusive(), Ok(true));
    FileExt::unlock(&file).ok();

    Ok((
        got,
        format!("杀死持锁进程后主进程重获锁={got}（OS 自动释放 stale 锁）"),
    ))
}

/// C：CAS activation。CURRENT 文件存当前 generation 号；
///    activate(expected_base, new) 只有在 CURRENT==expected_base 时才写入。
fn assertion_c_cas_activation(base: &Path) -> Result<(bool, String)> {
    let current = base.join("CURRENT");
    write_current(&current, 17)?;

    // 正确基线：expected=17 → 切到 18，应成功
    let ok1 = cas_activate(&current, 17, 18)?;
    // 过期基线：expected=17（但 CURRENT 已是 18）→ 切到 99，应被拒
    let ok2 = cas_activate(&current, 17, 99)?;
    let final_gen = read_current(&current)?;

    // 期望：ok1=true, ok2=false, final=18（99 没写进去）
    let pass = ok1 && !ok2 && final_gen == 18;
    Ok((
        pass,
        format!("首次CAS(17→18)={ok1}, 过期CAS(17→99)={ok2}, 最终CURRENT={final_gen}（应 18）"),
    ))
}

/// D：lease record。拿锁后往锁文件写 owner/pid/process_start/operation_id，
///    通过同一持锁句柄读回并验证字段存在。
fn assertion_d_lease_record(base: &Path) -> Result<(bool, String)> {
    let lock = base.join("lease_record.lock");
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock)?;
    anyhow::ensure!(
        file.try_lock_exclusive()?,
        "lease record lock unexpectedly busy"
    );

    let record = format!(
        "instance_id=inst-abc\npid={}\nprocess_start=2026-07-21T17:00:00Z\noperation_id=op-001\nfencing_token=42\n",
        std::process::id()
    );
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(record.as_bytes())?;
    file.flush()?;

    // Windows mandatory locking rejects a second handle while this exclusive lock is held.
    file.seek(SeekFrom::Start(0))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    FileExt::unlock(&file).ok();

    let has_all = buf.contains("instance_id=")
        && buf.contains("pid=")
        && buf.contains("process_start=")
        && buf.contains("operation_id=")
        && buf.contains("fencing_token=");
    Ok((
        has_all,
        format!("lease record 字段齐全={has_all}（instance/pid/start/op/fencing）"),
    ))
}

// ---- CAS 辅助 ----

fn write_current(path: &Path, gen: u64) -> Result<()> {
    std::fs::write(path, gen.to_string()).context("write CURRENT")
}

fn read_current(path: &Path) -> Result<u64> {
    let s = std::fs::read_to_string(path)?;
    Ok(s.trim().parse()?)
}

/// 模拟 activation 的 CAS：读 CURRENT，若等于 expected 则原子写 new。
/// 真实实现应在持有 writer lease 下做，这里 spike 单进程串行，聚焦语义正确性。
fn cas_activate(current: &Path, expected: u64, new: u64) -> Result<bool> {
    let cur = read_current(current)?;
    if cur != expected {
        return Ok(false);
    }
    // 先写临时文件再原子 rename（Windows 上 rename 到已存在目标用 replace 语义）
    let tmp = current.with_extension("tmp");
    std::fs::write(&tmp, new.to_string())?;
    std::fs::rename(&tmp, current).context("atomic rename CURRENT")?;
    Ok(true)
}

fn wait_for_line(stdout: &mut std::process::ChildStdout, needle: &str) -> Result<()> {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // EOF
        }
        if line.contains(needle) {
            return Ok(());
        }
    }
    anyhow::bail!("未等到子进程输出 {needle}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_record_is_readable_through_locked_handle() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let (passed, detail) = assertion_d_lease_record(tmp.path())?;

        assert!(passed, "{detail}");
        Ok(())
    }
}
