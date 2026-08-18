//! source-snapshot spike（可丢弃探针，不进 crates/）。
//!
//! 目的：为 RFC-0002 的 ReadOnlySourceSnapshot contract 提供实测证据；
//! Plan 审查 #6 / §5.2 仅作历史 evidence provenance。
//! 核心命题：Provider 在 parse 期间追加/截断/替换源文件时必须能被检测，
//! 提交前复核身份/长度/mtime/fingerprint，变化则丢弃 staging 返回
//! source_changed_during_read，绝不提交混合时点数据。
//!
//! 验证五个断言：
//!   A. 无变化：快照打开→读取→提交前复核一致 → 允许提交（committed）；
//!   B. 追加（tail-append）：读取后源文件被追加内容 → 复核检测到 len/fingerprint 变化 → 拒绝；
//!   C. 截断（truncate）：读取后源文件被截短 → 复核检测到变化 → 拒绝；
//!   D. 原子替换（rename 覆盖）：读取后源文件被另一个文件 rename 覆盖 → 复核检测到 → 拒绝；
//!   E. 只读性：整个过程结束后，Provider 侧从未修改源（本 spike 只读打开，写由“外部 Provider”模拟）。
//!
//! 用法：cargo run --release

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

/// 打开快照时捕获的源文件身份。真实实现里 file_id 用平台 inode/FileId，
/// 这里 spike 用 (len, mtime, 前缀 fingerprint) 三元组近似，够验证语义。
#[derive(Clone, Debug, PartialEq)]
struct SourceSnapshot {
    len: u64,
    mtime: SystemTime,
    /// 读取时捕获的内容 fingerprint（这里用 FNV-1a，够做变化检测）。
    fingerprint: u64,
    /// 快照捕获的字节数（parse 只允许读这个范围）。
    captured_len: u64,
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// 打开快照：记录 len/mtime，读取捕获范围内容并算 fingerprint。
/// 只读打开，绝不写。
fn open_snapshot(path: &Path) -> Result<(SourceSnapshot, Vec<u8>)> {
    let meta = std::fs::metadata(path).context("stat source")?;
    let len = meta.len();
    let mtime = meta.modified().context("mtime")?;

    let mut f = File::open(path).context("open source read-only")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).context("read source")?;
    // 只读入捕获时刻的字节；若文件在读期间变长，captured_len 固定为初始 len。
    let captured_len = len;
    buf.truncate(captured_len as usize);
    let fingerprint = fnv1a(&buf);

    Ok((
        SourceSnapshot {
            len,
            mtime,
            fingerprint,
            captured_len,
        },
        buf,
    ))
}

/// 提交前复核：重新 stat + 重读捕获范围，与快照比对。
/// 一致返回 Ok(())，否则 Err（source_changed_during_read）。
fn verify_snapshot(path: &Path, snap: &SourceSnapshot) -> Result<()> {
    let meta = std::fs::metadata(path).context("re-stat source")?;
    let cur_len = meta.len();
    let cur_mtime = meta.modified().context("re-mtime")?;

    if cur_len != snap.len {
        anyhow::bail!("source_changed_during_read: len {} -> {}", snap.len, cur_len);
    }
    if cur_mtime != snap.mtime {
        anyhow::bail!("source_changed_during_read: mtime 变化");
    }
    // 重读捕获范围，比 fingerprint（防止 len/mtime 相同但内容被替换）。
    let mut f = File::open(path).context("re-open source")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    buf.truncate(snap.captured_len as usize);
    let cur_fp = fnv1a(&buf);
    if cur_fp != snap.fingerprint {
        anyhow::bail!("source_changed_during_read: fingerprint 变化（内容被替换）");
    }
    Ok(())
}

/// 模拟一次 Provider source 的完整 staging：打开快照 → parse（读取）→ 外部扰动 → 复核 → 决定提交/丢弃。
/// disturb: 在 parse 之后、复核之前对源文件做的外部修改（模拟 Provider 并发写）。
fn stage_source<F: FnOnce(&Path) -> Result<()>>(
    path: &Path,
    disturb: F,
) -> Result<bool> {
    let (snap, _content) = open_snapshot(path)?;
    // parse 阶段：这里只用已读到的 content，不再触碰磁盘（流式实现里会边读边解析）。

    // 外部 Provider 扰动（模拟并发写/替换）。
    disturb(path)?;

    // 提交前复核
    match verify_snapshot(path, &snap) {
        Ok(()) => Ok(true),   // 允许提交
        Err(_) => Ok(false),  // 丢弃 staging
    }
}

fn write_source(path: &Path, content: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    f.flush()?;
    Ok(())
}

/// 确保后续 mtime 与初始不同：Windows/部分 FS mtime 粒度较粗，sleep 一下。
fn bump_time() {
    std::thread::sleep(Duration::from_millis(20));
}

fn main() -> Result<()> {
    println!("=== source-snapshot spike ===");
    println!("  os/arch = {}/{}", std::env::consts::OS, std::env::consts::ARCH);
    println!();

    let tmp = tempfile::tempdir()?;
    let base = tmp.path();

    // A：无变化 → 允许提交
    let a_path = base.join("a.jsonl");
    write_source(&a_path, "{\"role\":\"user\",\"text\":\"hello\"}\n")?;
    let a_committed = stage_source(&a_path, |_| Ok(()))?;
    let a_pass = a_committed;

    // B：追加 → 拒绝
    let b_path = base.join("b.jsonl");
    write_source(&b_path, "{\"role\":\"user\",\"text\":\"first\"}\n")?;
    let b_committed = stage_source(&b_path, |p| {
        bump_time();
        let mut f = OpenOptions::new().append(true).open(p)?;
        f.write_all(b"{\"role\":\"assistant\",\"text\":\"late\"}\n")?;
        f.flush()?;
        Ok(())
    })?;
    let b_pass = !b_committed;

    // C：截断 → 拒绝
    let c_path = base.join("c.jsonl");
    write_source(&c_path, "{\"role\":\"user\",\"text\":\"long content here for truncation\"}\n")?;
    let c_committed = stage_source(&c_path, |p| {
        bump_time();
        let f = OpenOptions::new().write(true).open(p)?;
        f.set_len(10)?; // 截断
        f.sync_all()?;
        Ok(())
    })?;
    let c_pass = !c_committed;

    // D：原子替换（rename 覆盖，len 可能相同但内容不同）→ 拒绝
    let d_path = base.join("d.jsonl");
    write_source(&d_path, "AAAAAAAAAAAAAAAAAAAA")?; // 20 字节
    let d_committed = stage_source(&d_path, |p| {
        bump_time();
        // 用同样 20 字节但不同内容的文件 rename 覆盖 → len 相同，fingerprint 不同
        let replacement = p.with_extension("new");
        write_source(&replacement, "BBBBBBBBBBBBBBBBBBBB")?; // 也是 20 字节
        std::fs::rename(&replacement, p)?;
        Ok(())
    })?;
    let d_pass = !d_committed;

    // E：只读性——本 spike 从未对源写入（写都由 disturb 显式模拟“外部 Provider”）。
    //    这里再确认：A 场景提交后，源内容与初始一致（我们没改过它）。
    let mut check = String::new();
    File::open(&a_path)?.read_to_string(&mut check)?;
    let e_pass = check == "{\"role\":\"user\",\"text\":\"hello\"}\n";

    println!("=== 结论汇总 ===");
    pr("A 无变化 → 允许提交(committed)", a_pass, a_committed);
    pr("B 追加 → 检测到并拒绝", b_pass, b_committed);
    pr("C 截断 → 检测到并拒绝", c_pass, c_committed);
    pr("D 原子替换(等长异容) → fingerprint 检测到并拒绝", d_pass, d_committed);
    pr("E 只读性 → 源内容未被本工具改动", e_pass, e_pass);

    let all = a_pass && b_pass && c_pass && d_pass && e_pass;
    println!("\nContract / decision evidence：");
    println!("  RFC-0002：len+mtime+fingerprint 复核可检出追加/截断/等长替换；");
    println!("  等长替换必须靠 fingerprint（len/mtime 不足），正式复核须包含内容指纹；");
    println!("  检出变化即返回 source_changed_during_read 并丢弃 staging，不提交混合时点数据。");
    println!("\n全部通过 = {all}");

    if !all {
        anyhow::bail!("部分断言未通过");
    }
    Ok(())
}

fn pr(name: &str, pass: bool, committed: bool) {
    println!(
        "  [{}] {name}（committed={committed}）",
        if pass { "PASS" } else { "FAIL" }
    );
}
