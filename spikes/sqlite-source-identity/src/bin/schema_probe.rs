use rusqlite::{Connection, OpenFlags};
fn main() {
    for path in std::env::args().skip(1) {
        println!("=== DB: {path}");
        let conn = match Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => { println!("  OPEN_FAILED: {e}"); continue; }
        };
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap_or_else(|e| format!("err:{e}"));
        let dv: i64 = conn.query_row("PRAGMA data_version", [], |r| r.get(0)).unwrap_or(-1);
        println!("  journal_mode={mode} data_version={dv}");
        let mut stmt = match conn.prepare(
            "SELECT type, name, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name",
        ) { Ok(s) => s, Err(e) => { println!("  MASTER_FAILED: {e}"); continue; } };
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?))
        });
        let rows = match rows { Ok(r) => r, Err(e) => { println!("  QUERY_FAILED: {e}"); continue; } };
        for row in rows.flatten() {
            let (kind, name, sql) = row;
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |r| r.get(0))
                .unwrap_or(-1);
            println!("  [{kind}] {name}  rows={count}");
            if let Some(sql) = sql {
                println!("      SQL: {}", sql.replace('\n', " ").replace("  ", " "));
            }
        }
    }
}
