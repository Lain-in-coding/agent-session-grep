//! sqlite-source-identity spike 第二阶段（可丢弃探针，不进 crates/）。
//!
//! 第一阶段（`src/main.rs`）证明行级身份可承担 SnapshotChanged 语义。
//! 本阶段补齐第一阶段明确列为未验证的三项缺口：
//!
//!   H. schema 漂移：真实 provider 表会经 ALTER TABLE 增列，行级身份必须在
//!      列集变化后仍稳定，且解析器不能因未知列而失败；
//!   I. 并发：provider 正在写库时读者能否取得一致行级快照，不被撕裂读影响；
//!   J. 规模性能：行级 BLAKE3 与 data_version 门在真实量级下的开销对比。
//!
//! 真实 schema 依据（本机只读探测所得，见 EVIDENCE.md）：
//!   Zed threads 表尾部形如 `data BLOB NOT NULL , parent_id TEXT, folder_paths TEXT,
//!   folder_paths_order TEXT, created_at TEXT` —— 逗号换行是 ALTER TABLE ADD COLUMN
//!   的痕迹，即该表确实经历过增量演进。本 spike 据此复现同形漂移。
//!
//! 用法：cargo run --release --bin phase2

use std::time::Instant;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};

struct Check {
    pass: bool,
    detail: String,
}

fn print_result(label: &str, pass: bool, detail: &str) {
    let tag = if pass { "[PASS]" } else { "[FAIL]" };
    println!("  {tag} {label} — {detail}");
}

/// 行级身份：主键 + 参与身份的列内容指纹。
///
/// 关键设计：指纹只覆盖「解析器实际消费的列」，而非 `SELECT *`。
/// 这样新增的无关列不会使既有快照失效——这是应对 schema 漂移的核心。
#[derive(Debug, Clone, PartialEq, Eq)]
struct RowSnapshot {
    row_key: String,
    fingerprint: String,
    /// 参与指纹计算的列名（有序），使快照自描述其身份依据。
    identity_columns: Vec<String>,
}

fn fingerprint_parts(parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        // 长度前缀分帧，避免相邻字段拼接产生歧义。
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_hex().to_string()
}

/// 运行时列解析：从候选名中挑第一个真实存在的列。
///
/// CCHV 对 ForgeCode 用的就是这个思路（`PRAGMA table_info` + 列名候选），
/// 本 spike 验证它能否与行级身份组合，使身份在 schema 漂移下保持稳定。
fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(cols)
}

fn pick<'a>(available: &[String], candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|c| available.iter().any(|a| a == c))
}

/// 按运行时解析出的列集读取行级快照。
///
/// `identity_candidates` 是「解析器关心的语义字段」的候选名列表；
/// 未解析到的候选被跳过，未知的新增列被忽略。
fn capture_row(
    conn: &Connection,
    table: &str,
    key_candidates: &[&str],
    identity_candidates: &[&[&str]],
    row_key: &str,
) -> Result<RowSnapshot> {
    let cols = table_columns(conn, table)?;
    let key_col = pick(&cols, key_candidates)
        .with_context(|| format!("no key column among {key_candidates:?}"))?;

    let mut identity_columns: Vec<String> = Vec::new();
    for candidates in identity_candidates {
        if let Some(found) = pick(&cols, candidates) {
            identity_columns.push(found.to_string());
        }
    }
    if identity_columns.is_empty() {
        bail!("no identity column resolved for table {table}");
    }

    let select_list = identity_columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {select_list} FROM \"{table}\" WHERE \"{key_col}\" = ?1");

    let values: Vec<Vec<u8>> = conn.query_row(&sql, [row_key], |row| {
        let mut out = Vec::new();
        for idx in 0..identity_columns.len() {
            // 统一按字节取，数值/文本/BLOB 都能覆盖；NULL 用零长度表示。
            let raw: Option<Vec<u8>> = match row.get_ref(idx)? {
                rusqlite::types::ValueRef::Null => None,
                rusqlite::types::ValueRef::Integer(i) => Some(i.to_string().into_bytes()),
                rusqlite::types::ValueRef::Real(f) => Some(f.to_string().into_bytes()),
                rusqlite::types::ValueRef::Text(t) => Some(t.to_vec()),
                rusqlite::types::ValueRef::Blob(b) => Some(b.to_vec()),
            };
            out.push(raw.unwrap_or_default());
        }
        Ok(out)
    })?;

    let refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();
    Ok(RowSnapshot {
        row_key: row_key.to_string(),
        fingerprint: fingerprint_parts(&refs),
        identity_columns,
    })
}

fn open_read_only(path: &std::path::Path) -> Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context("open read-only")
}

/// 断言 H：schema 漂移（ALTER TABLE ADD COLUMN）后行级身份保持稳定。
///
/// 复现 Zed threads 表的真实演进形态：先建初始列集，再增列。
fn assertion_h_schema_drift(base: &std::path::Path) -> Result<Check> {
    let db = base.join("drift.db");
    let conn = Connection::open(&db)?;
    // 初始 schema：仅有解析器最初认识的列。
    conn.execute_batch(
        "CREATE TABLE threads (
             id TEXT PRIMARY KEY,
             summary TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             data_type TEXT NOT NULL,
             data BLOB NOT NULL
         );",
    )?;
    conn.execute(
        "INSERT INTO threads(id, summary, updated_at, data_type, data)
         VALUES('t-keep', 'first thread', '2026-07-01T00:00:00Z', 'zstd', ?1)",
        [b"payload-bytes".as_slice()],
    )?;

    // 解析器关心的语义字段（各给出候选名，模拟跨 provider 命名差异）。
    let key_candidates = ["id", "thread_id", "conversation_id"];
    let identity: [&[&str]; 3] = [&["summary", "title"], &["data", "body"], &["data_type"]];

    let before = {
        let ro = open_read_only(&db)?;
        capture_row(&ro, "threads", &key_candidates, &identity, "t-keep")?
    };

    // 真实漂移：按 Zed 的实际形态增列，并给已有行回填新列。
    conn.execute_batch(
        "ALTER TABLE threads ADD COLUMN parent_id TEXT;
         ALTER TABLE threads ADD COLUMN folder_paths TEXT;
         ALTER TABLE threads ADD COLUMN folder_paths_order TEXT;
         ALTER TABLE threads ADD COLUMN created_at TEXT;",
    )?;
    conn.execute(
        "UPDATE threads SET folder_paths = '[\"/proj\"]', created_at = '2026-07-01T00:00:00Z'
         WHERE id = 't-keep'",
        [],
    )?;

    let after = {
        let ro = open_read_only(&db)?;
        capture_row(&ro, "threads", &key_candidates, &identity, "t-keep")?
    };

    let cols_after = table_columns(&conn, "threads")?;
    let grew = cols_after.len() == 9;
    let identity_stable = before.fingerprint == after.fingerprint;

    // 反向验证：语义字段真变化时必须被检出。
    conn.execute(
        "UPDATE threads SET summary = 'renamed thread' WHERE id = 't-keep'",
        [],
    )?;
    let renamed = {
        let ro = open_read_only(&db)?;
        capture_row(&ro, "threads", &key_candidates, &identity, "t-keep")?
    };
    let semantic_change_detected = renamed.fingerprint != after.fingerprint;

    // 列名差异适配：另一套命名的等价表应解析出对应列。
    conn.execute_batch(
        "CREATE TABLE conversations (
             conversation_id TEXT PRIMARY KEY,
             title TEXT NOT NULL,
             body BLOB NOT NULL,
             data_type TEXT NOT NULL
         );
         INSERT INTO conversations VALUES('c-1', 'first thread', x'7061796c6f61642d6279746573', 'zstd');",
    )?;
    let alt = {
        let ro = open_read_only(&db)?;
        capture_row(&ro, "conversations", &key_candidates, &identity, "c-1")?
    };
    // 同内容 + 同列顺序 → 与初始快照指纹一致，说明身份由内容而非表名决定。
    let cross_schema_match = alt.fingerprint == before.fingerprint;

    let pass = grew && identity_stable && semantic_change_detected && cross_schema_match;
    Ok(Check {
        pass,
        detail: format!(
            "列 5->{} , 增列后身份不变={identity_stable}, 语义变更被检出={semantic_change_detected}, 异名同义表身份一致={cross_schema_match}",
            cols_after.len()
        ),
    })
}

/// 断言 I：provider 并发写入时，读者取得的行级快照不撕裂。
///
/// WAL 下读者看到的是一致快照；本断言验证「读期间被写」不会产生
/// 半更新指纹，且写入完成后能被检出。
fn assertion_i_concurrent_write(base: &std::path::Path) -> Result<Check> {
    let db = base.join("concurrent.db");
    let writer = Connection::open(&db)?;
    writer.execute_batch("PRAGMA journal_mode=WAL;")?;
    writer.execute_batch(
        "CREATE TABLE threads (
             id TEXT PRIMARY KEY, summary TEXT NOT NULL,
             data_type TEXT NOT NULL, data BLOB NOT NULL
         );",
    )?;
    writer.execute(
        "INSERT INTO threads VALUES('t-1', 'original summary', 'plain', ?1)",
        [b"body-v1".as_slice()],
    )?;

    let key_candidates = ["id"];
    let identity: [&[&str]; 3] = [&["summary"], &["data"], &["data_type"]];

    let reader = open_read_only(&db)?;
    let baseline = capture_row(&reader, "threads", &key_candidates, &identity, "t-1")?;

    // 读者开启显式只读事务，取得一致性快照点。
    reader.execute_batch("BEGIN DEFERRED")?;
    let inside_before = capture_row(&reader, "threads", &key_candidates, &identity, "t-1")?;

    // 写者在读事务进行中提交一次多列更新（模拟 provider 改写会话）。
    let tx = writer.unchecked_transaction()?;
    tx.execute(
        "UPDATE threads SET summary = 'updated summary', data = ?1 WHERE id = 't-1'",
        [b"body-v2".as_slice()],
    )?;
    tx.commit()?;

    // 读事务内再次读取：应仍是事务开始时的快照，不含半更新。
    let inside_after = capture_row(&reader, "threads", &key_candidates, &identity, "t-1")?;
    let snapshot_isolated = inside_after.fingerprint == inside_before.fingerprint;
    reader.execute_batch("COMMIT")?;

    // 事务结束后重新读取：应检出写者的提交。
    let after_commit = capture_row(&reader, "threads", &key_candidates, &identity, "t-1")?;
    let change_detected = after_commit.fingerprint != baseline.fingerprint;

    // 并发写入期间读者不得阻塞失败（WAL 的关键收益）。
    let reader_never_blocked = true; // 上面所有读取均成功返回，未出现 SQLITE_BUSY。

    let pass = snapshot_isolated && change_detected && reader_never_blocked;
    Ok(Check {
        pass,
        detail: format!(
            "读事务内快照隔离={snapshot_isolated}, 提交后变更被检出={change_detected}, 读者未被并发写阻塞={reader_never_blocked}"
        ),
    })
}

/// 断言 J：真实量级下行级指纹与 data_version 门的开销。
///
/// 目的不是给出正式 SLO，而是确认「全库重算」与「O(1) 门」的数量级差异，
/// 从而判断增量方案是否真的必要。
fn assertion_j_scale_cost(base: &std::path::Path) -> Result<Check> {
    let db = base.join("scale.db");
    let conn = Connection::open(&db)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    conn.execute_batch(
        "CREATE TABLE threads (
             id TEXT PRIMARY KEY, summary TEXT NOT NULL,
             data_type TEXT NOT NULL, data BLOB NOT NULL
         );",
    )?;

    // 5000 会话 × 约 2KB transcript，接近重度用户的单 provider 量级。
    const ROWS: usize = 5000;
    const BODY: usize = 2048;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt =
            tx.prepare("INSERT INTO threads VALUES(?1, ?2, 'plain', ?3)")?;
        for i in 0..ROWS {
            let body = vec![b'a' + (i % 26) as u8; BODY];
            stmt.execute(rusqlite::params![
                format!("t-{i:06}"),
                format!("thread summary {i}"),
                body
            ])?;
        }
    }
    tx.commit()?;

    let ro = open_read_only(&db)?;

    // 全量行级指纹：读全表并逐行哈希。
    let full_start = Instant::now();
    let mut stmt = ro.prepare("SELECT id, summary, data, data_type FROM threads")?;
    let mut hashed = 0usize;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let summary: String = row.get(1)?;
        let data: Vec<u8> = row.get(2)?;
        let dtype: String = row.get(3)?;
        let fp = fingerprint_parts(&[summary.as_bytes(), &data, dtype.as_bytes()]);
        debug_assert!(!fp.is_empty() && !id.is_empty());
        hashed += 1;
    }
    let full_ms = full_start.elapsed().as_secs_f64() * 1000.0;

    // data_version 门：O(1) 判定库是否变过。
    let gate_start = Instant::now();
    const GATE_ITERS: usize = 1000;
    for _ in 0..GATE_ITERS {
        let _dv: i64 = ro.query_row("PRAGMA data_version", [], |r| r.get(0))?;
    }
    let gate_us = gate_start.elapsed().as_secs_f64() * 1_000_000.0 / GATE_ITERS as f64;

    // 单行重算：命中变更后只需重算受影响行。
    let single_start = Instant::now();
    const SINGLE_ITERS: usize = 200;
    let key_candidates = ["id"];
    let identity: [&[&str]; 3] = [&["summary"], &["data"], &["data_type"]];
    for i in 0..SINGLE_ITERS {
        let key = format!("t-{:06}", i * 7 % ROWS);
        let _ = capture_row(&ro, "threads", &key_candidates, &identity, &key)?;
    }
    let single_ms = single_start.elapsed().as_secs_f64() * 1000.0 / SINGLE_ITERS as f64;

    let db_bytes = std::fs::metadata(&db)?.len();
    // 判定：门必须比全量重算便宜几个数量级，否则增量方案没有意义。
    let gate_is_cheap = (gate_us / 1000.0) < full_ms / 100.0;
    let all_rows_hashed = hashed == ROWS;

    let pass = gate_is_cheap && all_rows_hashed;
    Ok(Check {
        pass,
        detail: format!(
            "{ROWS} 行/{db_bytes} 字节: 全量行级指纹={full_ms:.1}ms, 单行重算={single_ms:.3}ms, data_version 门={gate_us:.1}µs, 门比全量便宜两个数量级以上={gate_is_cheap}"
        ),
    })
}

fn main() -> Result<()> {
    println!("=== sqlite-source-identity spike / phase 2 ===");
    println!("环境记录：");
    println!("  os            = {}", std::env::consts::OS);
    println!("  arch          = {}", std::env::consts::ARCH);
    println!("  sqlite_version= {}", rusqlite::version());

    let tmp = tempfile::tempdir().context("create temp dir")?;
    let base = tmp.path();

    let h = assertion_h_schema_drift(base)?;
    let i = assertion_i_concurrent_write(base)?;
    let j = assertion_j_scale_cost(base)?;

    println!("\n=== 结论汇总 ===");
    print_result("H schema 漂移下行级身份稳定", h.pass, &h.detail);
    print_result("I 并发写入下读快照一致", i.pass, &i.detail);
    print_result("J 规模开销与 O(1) 门", j.pass, &j.detail);

    println!("\nContract / decision evidence：");
    println!("  H 成立 → 指纹只覆盖解析器消费的列 + 运行时列名解析，可吸收 ALTER TABLE 增列；");
    println!("  I 成立 → WAL 只读事务提供一致读取点，并发写不产生撕裂指纹，提交后可检出；");
    println!("  J 成立 → data_version 门与全量重算差两个数量级以上，增量方案有实际收益。");

    if h.pass && i.pass && j.pass {
        Ok(())
    } else {
        bail!("one or more phase-2 assertions failed")
    }
}
