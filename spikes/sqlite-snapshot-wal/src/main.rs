//! sqlite-snapshot-wal spike（可丢弃探针，不进 crates/）。
//!
//! 目的：为不可变 Generation Bundle、WAL 一致快照及历史审查证据 #13
//! （"裸复制 .sqlite 会丢失未 checkpoint 的已提交事务"）提供 Windows 上的实测证据。
//!
//! 验证四个断言：
//!   A. WAL 模式下裸复制主库文件（不含 -wal）会丢失已提交但未 checkpoint 的事务；
//!   B. SQLite Online Backup API 能生成一致快照，不丢事务；
//!   C. VACUUM INTO 也能生成一致快照（备选方案）；
//!   D. 旧 generation 快照在有新连接持续写入时仍可只读打开并读到冻结数据。
//!
//! 用法：cargo run --release

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{backup::Backup, Connection, OpenFlags};

const N_ROWS: i64 = 5_000;

fn main() -> Result<()> {
    println!("=== sqlite-snapshot-wal spike ===");
    print_env();

    let tmp = tempfile::tempdir()?;
    let base = tmp.path();

    let a = assertion_a_raw_copy_loses_data(base)?;
    let b = assertion_b_backup_api_consistent(base)?;
    let c = assertion_c_vacuum_into_consistent(base)?;
    let d = assertion_d_old_snapshot_readable_during_write(base)?;

    println!("\n=== 结论汇总 ===");
    print_result("A 裸复制主库(缺 -wal)丢数据", a.pass, &a.detail);
    print_result("B Backup API 一致快照", b.pass, &b.detail);
    print_result("C VACUUM INTO 一致快照", c.pass, &c.detail);
    print_result("D 旧快照写入期间可只读打开", d.pass, &d.detail);

    println!("\nContract / decision evidence：");
    println!("  快照实现：Backup API / VACUUM INTO 通过 → 正式 bundle 快照禁止裸 fs::copy 主库；");
    println!("  不可变 bundle：旧快照只读打开成立 → 可作为 cursor 分页 pinning 的证据输入；");
    println!("  历史审查#13：断言 A 若复现，即坐实裸复制丢事务风险，正式存储记录应引用本证据。");

    if a.pass && b.pass && c.pass && d.pass {
        Ok(())
    } else {
        anyhow::bail!("one or more sqlite-snapshot-wal assertions failed")
    }
}

struct Check {
    pass: bool,
    detail: String,
}

fn print_env() {
    println!("环境记录：");
    println!("  os            = {}", std::env::consts::OS);
    println!("  arch          = {}", std::env::consts::ARCH);
    println!("  sqlite_version= {}", rusqlite::version());
}

fn print_result(name: &str, pass: bool, detail: &str) {
    let mark = if pass { "PASS" } else { "FAIL" };
    println!("  [{mark}] {name} — {detail}");
}

/// 写入 N_ROWS 行到 WAL 库，保持连接打开（不 checkpoint），返回连接与库路径。
fn seed_wal_db(path: &Path) -> Result<Connection> {
    let _ = std::fs::remove_file(path);
    let conn = Connection::open(path).context("open db")?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA wal_autocheckpoint=0;", // 关闭自动 checkpoint，逼出"数据只在 -wal 里"的状态
    )?;
    conn.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT NOT NULL);")?;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare("INSERT INTO t(id, v) VALUES (?1, ?2)")?;
        for i in 0..N_ROWS {
            stmt.execute(rusqlite::params![i, format!("row-{i}")])?;
        }
    }
    tx.commit()?; // 已提交，但因 wal_autocheckpoint=0 仍主要在 -wal 中
    Ok(conn)
}

fn count_rows(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?)
}

/// A：裸复制主库文件（不含 -wal / -shm），另开只读连接，看能否读到全部行。
fn assertion_a_raw_copy_loses_data(base: &Path) -> Result<Check> {
    let src = base.join("a_src.sqlite");
    let live = seed_wal_db(&src)?;
    let live_count = count_rows(&live)?;

    // 只复制主库文件，故意不复制 -wal / -shm（模拟错误的 bundle 快照）。
    let dst = base.join("a_copy.sqlite");
    std::fs::copy(&src, &dst).context("raw copy main db")?;

    // 以只读、且不自动应用 wal 的方式打开副本。用 immutable 防止它去找 -wal。
    let uri = format!("file:{}?immutable=1", dst.to_string_lossy().replace('\\', "/"));
    let copy_conn = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .context("open raw copy immutable")?;

    let copy_count = count_rows(&copy_conn).unwrap_or(-1);
    drop(live);

    // 断言"通过"= 复现了数据丢失（copy_count < live_count），从而证明裸复制危险。
    let pass = copy_count < live_count;
    Ok(Check {
        pass,
        detail: format!("live={live_count} 行, 裸复制副本读到={copy_count} 行（副本更少即坐实风险）"),
    })
}

/// B：用 Online Backup API 生成快照，另开只读连接，应读到全部行。
fn assertion_b_backup_api_consistent(base: &Path) -> Result<Check> {
    let src = base.join("b_src.sqlite");
    let live = seed_wal_db(&src)?;
    let live_count = count_rows(&live)?;

    let dst = base.join("b_snapshot.sqlite");
    let _ = std::fs::remove_file(&dst);
    {
        let mut snap = Connection::open(&dst)?;
        let backup = Backup::new_with_names(
            &live,
            c"main",
            &mut snap,
            c"main",
        )?;
        backup.run_to_completion(100, std::time::Duration::from_millis(0), None)?;
    }

    let snap_ro = open_readonly(&dst)?;
    let snap_count = count_rows(&snap_ro)?;
    drop(live);

    let pass = snap_count == live_count;
    Ok(Check {
        pass,
        detail: format!("live={live_count} 行, Backup 快照读到={snap_count} 行（相等即一致）"),
    })
}

/// C：用 VACUUM INTO 生成快照。
fn assertion_c_vacuum_into_consistent(base: &Path) -> Result<Check> {
    let src = base.join("c_src.sqlite");
    let live = seed_wal_db(&src)?;
    let live_count = count_rows(&live)?;

    let dst = base.join("c_snapshot.sqlite");
    let _ = std::fs::remove_file(&dst);
    let dst_sql = dst.to_string_lossy().replace('\'', "''");
    live.execute(&format!("VACUUM INTO '{dst_sql}'"), [])
        .context("VACUUM INTO")?;

    let snap_ro = open_readonly(&dst)?;
    let snap_count = count_rows(&snap_ro)?;
    drop(live);

    let pass = snap_count == live_count;
    Ok(Check {
        pass,
        detail: format!("live={live_count} 行, VACUUM INTO 快照读到={snap_count} 行（相等即一致）"),
    })
}

/// D：生成快照后，源库继续写入；旧快照应只读打开且读到冻结时的行数（不受后续写入影响）。
fn assertion_d_old_snapshot_readable_during_write(base: &Path) -> Result<Check> {
    let src = base.join("d_src.sqlite");
    let live = seed_wal_db(&src)?;
    let frozen_count = count_rows(&live)?;

    // 用 Backup API 生成"旧 generation"快照。
    let snap_path = base.join("d_gen_old.sqlite");
    let _ = std::fs::remove_file(&snap_path);
    {
        let mut snap = Connection::open(&snap_path)?;
        let backup = Backup::new_with_names(&live, c"main", &mut snap, c"main")?;
        backup.run_to_completion(100, std::time::Duration::from_millis(0), None)?;
    }

    // 打开旧快照只读连接（模拟 cursor 固定到旧 generation）。
    let old_ro = open_readonly(&snap_path)?;

    // 源库继续写入新数据（模拟新一轮 sync）。
    {
        let tx = live.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare("INSERT INTO t(id, v) VALUES (?1, ?2)")?;
            for i in N_ROWS..(N_ROWS + 1000) {
                stmt.execute(rusqlite::params![i, format!("new-{i}")])?;
            }
        }
        tx.commit()?;
    }
    let live_after = count_rows(&live)?;
    let old_after = count_rows(&old_ro)?; // 应仍等于 frozen_count

    drop(old_ro);
    drop(live);

    let pass = old_after == frozen_count && live_after > frozen_count;
    Ok(Check {
        pass,
        detail: format!(
            "冻结时={frozen_count}, 写入后源库={live_after}, 旧快照仍读={old_after}（旧快照不变即成立）"
        ),
    })
}

fn open_readonly(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open readonly {}", path.display()))
}

#[allow(dead_code)]
fn abspath(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}
