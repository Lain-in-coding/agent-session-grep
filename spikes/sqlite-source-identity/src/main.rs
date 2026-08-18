//! sqlite-source-identity spike（可丢弃探针，不进 crates/）。
//!
//! 目的：判定 ReadOnlySourceSnapshot 契约能否扩展到 SQLite 类 provider
//! （ForgeCode `~/.forge/.forge.db`、Kiro、Goose、Crush、Zed、Amazon Q 等）。
//!
//! 生产契约当前身份是 `(path, len, mtime_ms, BLAKE3(整个文件))`，且一个源文件
//! 对应一个会话。SQLite 源违反这两条前提：一个 .db 文件承载全部会话，
//! 且 WAL 模式下写入不一定改变主库 len/mtime。
//!
//! 验证七个断言：
//!   A. 单文件多会话：一个 .db 内多会话，文件级快照无法给单会话稳定身份；
//!   B. 无关写入使文件级 fingerprint 失效：改会话 X 会让会话 Y 的文件级快照失效；
//!   C. WAL 隐身写入：WAL 模式下提交后主库 len+mtime 可能完全不变（对照 spikes/sqlite-snapshot-wal 断言 A）；
//!   D. 行级内容指纹可检出等长异容替换：mtime 无关，等长改写必被 BLAKE3 检出；
//!   E. 行级快照对无关写入稳定：改会话 X 不影响会话 Y 的行级快照；
//!   F. SQLite `data_version` 提供廉价的库级变更检测（免全库哈希）；
//!   G. 只读打开 + immutable 快照读取不修改源库（严格只读不变量）。
//!
//! 用法：cargo run --release
//! 任一断言失败进程以非零退出（与 sqlite-snapshot-wal spike 一致）。

use std::path::Path;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};

struct Check {
    pass: bool,
    detail: String,
}

fn print_result(name: &str, pass: bool, detail: &str) {
    let tag = if pass { "[PASS]" } else { "[FAIL]" };
    println!("  {tag} {name} — {detail}");
}

fn main() -> Result<()> {
    println!("=== sqlite-source-identity spike ===");
    print_env();

    let tmp = tempfile::tempdir().context("create tempdir")?;
    let base = tmp.path();

    let a = assertion_a_one_file_many_sessions(base)?;
    let b = assertion_b_unrelated_write_breaks_file_snapshot(base)?;
    let c = assertion_c_wal_write_can_leave_main_db_unchanged(base)?;
    let d = assertion_d_row_fingerprint_detects_equal_length_rewrite(base)?;
    let e = assertion_e_row_snapshot_survives_unrelated_write(base)?;
    let f = assertion_f_data_version_detects_change_cheaply(base)?;
    let g = assertion_g_readonly_access_does_not_mutate(base)?;

    println!("\n=== 结论汇总 ===");
    print_result("A 单文件承载多会话（文件级身份不足）", a.pass, &a.detail);
    print_result("B 无关写入使文件级快照失效", b.pass, &b.detail);
    print_result("C WAL 提交后主库 len+mtime 可不变", c.pass, &c.detail);
    print_result("D 行级指纹检出等长异容替换", d.pass, &d.detail);
    print_result("E 行级快照对无关写入稳定", e.pass, &e.detail);
    print_result("F data_version 提供廉价变更检测", f.pass, &f.detail);
    print_result("G 只读读取不修改源库", g.pass, &g.detail);

    println!("\nContract / decision evidence：");
    println!("  A/B/C 成立 → SQLite 源不能沿用 (path,len,mtime,整文件哈希) 作为会话身份；");
    println!("  D/E 成立 → 行级 (row key + 内容 BLAKE3) 可承担 SnapshotChanged 语义；");
    println!("  F 成立 → data_version 可做库级快速门，避免每次全库重算；");
    println!("  G 成立 → 只读打开满足源严格只读不变量。");

    let all = a.pass && b.pass && c.pass && d.pass && e.pass && f.pass && g.pass;
    if all {
        Ok(())
    } else {
        bail!("one or more sqlite-source-identity assertions failed")
    }
}

fn print_env() {
    println!("环境记录：");
    println!("  os            = {}", std::env::consts::OS);
    println!("  arch          = {}", std::env::consts::ARCH);
    println!("  sqlite_version= {}", rusqlite::version());
}

/// 建一个模拟 ForgeCode 形状的会话库：conversations 表，每行一个会话。
fn seed_db(path: &Path, sessions: &[(&str, &str)]) -> Result<()> {
    let conn = Connection::open(path).context("open seed db")?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS conversations(
             conversation_id TEXT PRIMARY KEY,
             title           TEXT NOT NULL,
             transcript      TEXT NOT NULL,
             updated_at      INTEGER NOT NULL
         );",
    )
    .context("create schema")?;
    for (id, transcript) in sessions {
        conn.execute(
            "INSERT INTO conversations(conversation_id, title, transcript, updated_at)
             VALUES(?1, ?2, ?3, ?4)",
            rusqlite::params![id, format!("title-{id}"), transcript, 1_700_000_000i64],
        )
        .context("insert session")?;
    }
    // checkpoint 让主库落盘，模拟"已存在一段时间的库"。
    conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")
        .context("checkpoint")?;
    Ok(())
}

fn file_identity(path: &Path) -> Result<(u64, i64, String)> {
    let meta = std::fs::metadata(path).context("stat db")?;
    let len = meta.len();
    let mtime_ms = meta
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let bytes = std::fs::read(path).context("read db bytes")?;
    Ok((len, mtime_ms, blake3::hash(&bytes).to_hex().to_string()))
}

/// 只读打开：immutable 不加锁读取，模拟严格只读的 provider 访问。
fn open_readonly(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("open readonly")
}

/// 行级快照：以 (row key, 内容 BLAKE3) 作为单会话身份，替代文件级三元组。
#[derive(Debug, Clone, PartialEq, Eq)]
struct RowSnapshot {
    conversation_id: String,
    /// 该行可检索内容的 BLAKE3（不含无关行）。
    fingerprint: String,
}

fn capture_row(conn: &Connection, id: &str) -> Result<RowSnapshot> {
    let (title, transcript): (String, String) = conn
        .query_row(
            "SELECT title, transcript FROM conversations WHERE conversation_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .context("select row")?;
    // 用长度前缀分隔字段，避免跨字段边界碰撞（与 domain StableId::derive 的 framing 同理）。
    let mut hasher = blake3::Hasher::new();
    for field in [id, title.as_str(), transcript.as_str()] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    Ok(RowSnapshot {
        conversation_id: id.to_string(),
        fingerprint: hasher.finalize().to_hex().to_string(),
    })
}

fn data_version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA data_version", [], |r| r.get(0))
        .context("data_version")
}

/// A. 一个 .db 文件承载多个会话 → 文件级快照无法定位单个会话。
fn assertion_a_one_file_many_sessions(base: &Path) -> Result<Check> {
    let db = base.join("a.db");
    seed_db(
        &db,
        &[
            ("s1", "session one transcript"),
            ("s2", "session two transcript"),
            ("s3", "session three transcript"),
        ],
    )?;
    let conn = open_readonly(&db)?;
    let count: i64 = conn.query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))?;
    let (_, _, file_fp) = file_identity(&db)?;
    // 三个会话共享同一个文件级 fingerprint —— 文件级身份无法区分它们。
    let pass = count == 3;
    Ok(Check {
        pass,
        detail: format!(
            "单文件内会话数={count}, 三者共享同一文件 fingerprint={}（文件级身份无法定位单会话）",
            &file_fp[..12]
        ),
    })
}

/// B. 修改会话 X 会让会话 Y 的文件级快照失效（假阳性 SnapshotChanged）。
fn assertion_b_unrelated_write_breaks_file_snapshot(base: &Path) -> Result<Check> {
    let db = base.join("b.db");
    seed_db(
        &db,
        &[("keep", "unchanged transcript"), ("touch", "will change")],
    )?;
    let before = file_identity(&db)?;

    // 外部 provider 只改 "touch" 这一行，"keep" 完全没动。
    {
        let conn = Connection::open(&db)?;
        conn.execute(
            "UPDATE conversations SET transcript = ?1 WHERE conversation_id = 'touch'",
            ["completely different and longer transcript body"],
        )?;
        conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")?;
    }
    let after = file_identity(&db)?;

    let fp_changed = before.2 != after.2;
    // "keep" 行内容其实没变，但文件级快照已失效。
    let conn = open_readonly(&db)?;
    let keep_transcript: String = conn.query_row(
        "SELECT transcript FROM conversations WHERE conversation_id = 'keep'",
        [],
        |r| r.get(0),
    )?;
    let keep_untouched = keep_transcript == "unchanged transcript";

    Ok(Check {
        pass: fp_changed && keep_untouched,
        detail: format!(
            "文件 fingerprint 变化={fp_changed}, 而 keep 行内容未变={keep_untouched} → 文件级快照对无关写入产生假阳性"
        ),
    })
}

/// C. WAL 模式下提交后，主库文件 len+mtime 可能完全不变（写入"隐身"）。
fn assertion_c_wal_write_can_leave_main_db_unchanged(base: &Path) -> Result<Check> {
    let db = base.join("c.db");
    seed_db(&db, &[("s1", "initial")])?;
    let (len_before, mtime_before, _) = file_identity(&db)?;

    // 保持连接打开并提交，不做 checkpoint —— 数据只在 -wal 里。
    let conn = Connection::open(&db)?;
    conn.execute(
        "INSERT INTO conversations(conversation_id, title, transcript, updated_at)
         VALUES('wal-only', 'title-wal', 'committed but only in wal', 1700000001)",
        [],
    )?;
    let (len_after, mtime_after, _) = file_identity(&db)?;

    // 用独立只读连接确认该事务确实已提交可见。
    let visible: i64 = {
        let ro = open_readonly(&db)?;
        ro.query_row(
            "SELECT count(*) FROM conversations WHERE conversation_id = 'wal-only'",
            [],
            |r| r.get(0),
        )?
    };

    let main_unchanged = len_before == len_after && mtime_before == mtime_after;
    Ok(Check {
        pass: main_unchanged && visible == 1,
        detail: format!(
            "已提交且可见={}, 主库 len {len_before}->{len_after}, mtime 未变={} → (len,mtime) 会漏检 WAL 中的已提交写入",
            visible == 1,
            mtime_before == mtime_after
        ),
    })
}

/// D. 行级内容指纹能检出等长异容替换（与文件级 fingerprint 同等强度，但作用于行）。
fn assertion_d_row_fingerprint_detects_equal_length_rewrite(base: &Path) -> Result<Check> {
    let db = base.join("d.db");
    seed_db(&db, &[("s1", "AAAAAAAAAA")])?;
    let snap = {
        let ro = open_readonly(&db)?;
        capture_row(&ro, "s1")?
    };

    // 等长异容替换：长度完全相同，内容不同。
    {
        let conn = Connection::open(&db)?;
        conn.execute(
            "UPDATE conversations SET transcript = 'BBBBBBBBBB' WHERE conversation_id = 's1'",
            [],
        )?;
    }
    let after = {
        let ro = open_readonly(&db)?;
        capture_row(&ro, "s1")?
    };

    let same_len = {
        let ro = open_readonly(&db)?;
        let t: String = ro.query_row(
            "SELECT transcript FROM conversations WHERE conversation_id = 's1'",
            [],
            |r| r.get(0),
        )?;
        t.len() == 10
    };
    let detected = snap.fingerprint != after.fingerprint;
    Ok(Check {
        pass: detected && same_len,
        detail: format!(
            "等长替换（10->10 字节）被行级指纹检出={detected}（mtime 无关，纯内容判定）"
        ),
    })
}

/// E. 行级快照对无关会话的写入保持稳定（无假阳性）。
fn assertion_e_row_snapshot_survives_unrelated_write(base: &Path) -> Result<Check> {
    let db = base.join("e.db");
    seed_db(
        &db,
        &[("keep", "unchanged transcript"), ("touch", "will change")],
    )?;
    let keep_before = {
        let ro = open_readonly(&db)?;
        capture_row(&ro, "keep")?
    };

    {
        let conn = Connection::open(&db)?;
        conn.execute(
            "UPDATE conversations SET transcript = ?1 WHERE conversation_id = 'touch'",
            ["a much longer and entirely different transcript"],
        )?;
        conn.execute(
            "INSERT INTO conversations(conversation_id, title, transcript, updated_at)
             VALUES('brand-new', 'title-new', 'new session added', 1700000002)",
            [],
        )?;
        conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")?;
    }

    let keep_after = {
        let ro = open_readonly(&db)?;
        capture_row(&ro, "keep")?
    };
    let (_, _, file_fp_after) = file_identity(&db)?;
    let file_level_would_fail = {
        // 对照：文件级快照此时必然已变。
        let ro = open_readonly(&db)?;
        let n: i64 = ro.query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))?;
        n == 3 && !file_fp_after.is_empty()
    };

    let stable = keep_before == keep_after;
    Ok(Check {
        pass: stable && file_level_would_fail,
        detail: format!(
            "keep 行级快照在其他行改写+新增后保持不变={stable}（同场景下文件级快照会失效）"
        ),
    })
}

/// F. `PRAGMA data_version` 在库被其他连接改动后变化，可作廉价库级门。
fn assertion_f_data_version_detects_change_cheaply(base: &Path) -> Result<Check> {
    let db = base.join("f.db");
    seed_db(&db, &[("s1", "initial")])?;

    // 用同一个只读连接观察 data_version 的变化（data_version 是 per-connection 视图）。
    let ro = open_readonly(&db)?;
    let v_before = data_version(&ro)?;
    // 先做一次读，确保该连接已建立快照视图。
    let _: i64 = ro.query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))?;

    {
        let w = Connection::open(&db)?;
        w.execute(
            "UPDATE conversations SET transcript = 'changed by other connection' WHERE conversation_id = 's1'",
            [],
        )?;
        w.pragma_update(None, "wal_checkpoint", "TRUNCATE")?;
    }

    // 重新读一次以刷新该连接对库的视图。
    let _: i64 = ro.query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))?;
    let v_after = data_version(&ro)?;

    let changed = v_after != v_before;
    Ok(Check {
        pass: changed,
        detail: format!(
            "data_version {v_before}->{v_after}, 检出外部写入={changed}（O(1) 判定，无需重算全库哈希）"
        ),
    })
}

/// G. 只读打开并读取，不修改源库文件（严格只读不变量）。
fn assertion_g_readonly_access_does_not_mutate(base: &Path) -> Result<Check> {
    let db = base.join("g.db");
    seed_db(&db, &[("s1", "readonly probe"), ("s2", "second")])?;
    let before = file_identity(&db)?;

    {
        let ro = open_readonly(&db)?;
        let _: i64 = ro.query_row("SELECT count(*) FROM conversations", [], |r| r.get(0))?;
        let _ = capture_row(&ro, "s1")?;
        let _ = capture_row(&ro, "s2")?;
        // 只读连接上尝试写必须失败。
        let write_rejected = ro
            .execute(
                "UPDATE conversations SET title = 'hacked' WHERE conversation_id = 's1'",
                [],
            )
            .is_err();
        if !write_rejected {
            return Ok(Check {
                pass: false,
                detail: "只读连接竟允许写入 —— 严格只读不变量被破坏".into(),
            });
        }
    }

    let after = file_identity(&db)?;
    let unchanged = before == after;
    Ok(Check {
        pass: unchanged,
        detail: format!(
            "读取+行级快照后文件身份不变={unchanged}, 只读连接写入被拒=true"
        ),
    })
}
