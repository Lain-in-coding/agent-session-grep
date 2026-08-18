//! FTS5 后端（rusqlite bundled，自带 SQLite + FTS5）。
//! 用 external-content 模式：内容表存原文，FTS5 表只存预分析 token，
//! 用触发器保持同步。查询侧同样用 analyzer 预分析。

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::analyzer::analyze_to_string;
use crate::corpus::{Doc, QueryCase};
use crate::BackendReport;

pub fn run(dir: &Path, docs: &[Doc], queries: &[QueryCase]) -> Result<BackendReport> {
    let db_path = dir.join("catalog.sqlite");
    let _ = std::fs::remove_file(&db_path);
    let conn = Connection::open(&db_path).context("open sqlite")?;

    // 探针配置：WAL + NORMAL + busy_timeout；正式约束由存储规范/ADR 维护。
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=30000;",
    )?;

    // 内容表只存原文（= Canonical catalog 本身，任何引擎都需要）。
    // FTS5 用 contentless（content=''）：只把预分析 token 喂给索引，不持久化分析串，
    // 与 Tantivy「存原文 + 独立索引」完全对等，消除体积对比的混淆变量。
    conn.execute_batch(
        "CREATE TABLE docs(
            id INTEGER PRIMARY KEY,
            provider TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
         );
         CREATE VIRTUAL TABLE docs_fts USING fts5(
            title_idx, body_idx,
            content='',
            tokenize='unicode61 remove_diacritics 0'
         );",
    )?;

    let build_start = Instant::now();
    {
        let tx = conn.unchecked_transaction()?;
        {
            let mut doc_stmt = tx.prepare(
                "INSERT INTO docs(id, provider, title, body)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut fts_stmt = tx.prepare(
                "INSERT INTO docs_fts(rowid, title_idx, body_idx)
                 VALUES (?1, ?2, ?3)",
            )?;
            for d in docs {
                doc_stmt.execute(rusqlite::params![
                    d.id as i64, d.provider, d.title, d.body
                ])?;
                let title_idx = analyze_to_string(&d.title);
                let body_idx = analyze_to_string(&d.body);
                fts_stmt.execute(rusqlite::params![d.id as i64, title_idx, body_idx])?;
            }
        }
        tx.commit()?;
    }
    conn.execute_batch("INSERT INTO docs_fts(docs_fts) VALUES('optimize');")?;
    // WAL checkpoint（TRUNCATE）落盘，避免测量时 -wal 文件虚增体积。
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let build_ms = build_start.elapsed().as_millis();

    // 查询：把 query 也预分析成 token，用 FTS5 MATCH（token OR token ...）。
    let mut recalls = Vec::new();
    let mut query_latencies_us = Vec::new();
    for q in queries {
        let tokens = crate::analyzer::analyze(&q.query);
        let match_expr = fts5_match_expr(&tokens);

        let start = Instant::now();
        let mut stmt = conn.prepare(
            "SELECT rowid FROM docs_fts WHERE docs_fts MATCH ?1
             ORDER BY bm25(docs_fts) LIMIT 10",
        )?;
        let ids: Vec<u64> = stmt
            .query_map([&match_expr], |r| r.get::<_, i64>(0).map(|v| v as u64))?
            .collect::<std::result::Result<_, _>>()?;
        let elapsed_us = start.elapsed().as_micros();
        query_latencies_us.push((q.name.clone(), elapsed_us));

        let recall = recall_at_10(&ids, &q.relevant);
        recalls.push((q.name.clone(), recall));
    }

    let index_bytes = dir_size(dir)?;
    Ok(BackendReport {
        name: "SQLite FTS5".to_string(),
        build_ms,
        index_bytes,
        recalls,
        query_latencies_us,
    })
}

/// 把 token 列表拼成 FTS5 MATCH 表达式：每个 token 加引号防语法冲突，OR 连接。
fn fts5_match_expr(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn recall_at_10(retrieved: &[u64], relevant: &BTreeSet<u64>) -> f64 {
    if relevant.is_empty() {
        return 1.0;
    }
    let top: BTreeSet<u64> = retrieved.iter().take(10).copied().collect();
    let hit = relevant.iter().filter(|r| top.contains(r)).count();
    hit as f64 / relevant.len().min(10) as f64
}

fn dir_size(dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // 只统计 catalog 相关文件
            if name.starts_with("catalog.sqlite") {
                total += meta.len();
            }
        }
    }
    Ok(total)
}
