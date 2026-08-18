//! search-backend spike harness（可丢弃探针，不进 crates/）。
//!
//! 目的：在同一套合成语料 + qrels + backend-neutral analyzer 下，
//! 对 SQLite FTS5 与 Tantivy 度量 recall@10 / 索引体积 / 构建时间 / 查询延迟，
//! 为 ADR-0001 的全文检索引擎决策提供对照证据。
//!
//! 用法：
//!   cargo run --release -- [文档数]
//! 默认 20000 篇。

mod analyzer;
mod corpus;
mod fts5;
mod tantivy_be;

/// 单个引擎的度量结果。
pub struct BackendReport {
    pub name: String,
    pub build_ms: u128,
    pub index_bytes: u64,
    pub recalls: Vec<(String, f64)>,
    pub query_latencies_us: Vec<(String, u128)>,
}

impl BackendReport {
    fn mean_recall(&self) -> f64 {
        if self.recalls.is_empty() {
            return 0.0;
        }
        self.recalls.iter().map(|(_, r)| r).sum::<f64>() / self.recalls.len() as f64
    }
    fn p_latency_us(&self) -> u128 {
        // 简单取最大值作为保守上界（query 数很少）
        self.query_latencies_us
            .iter()
            .map(|(_, v)| *v)
            .max()
            .unwrap_or(0)
    }
}

fn main() -> anyhow::Result<()> {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    println!("=== search-backend spike ===");
    print_environment(n);

    let (docs, queries) = corpus::build(n);
    println!(
        "\n语料：{} 篇文档，{} 条评测查询",
        docs.len(),
        queries.len()
    );
    for q in &queries {
        println!("  - {:<40} relevant={}", q.name, q.relevant.len());
    }

    let tmp = tempfile::tempdir()?;

    println!("\n--- 构建并评测 FTS5 ---");
    let fts5_report = fts5::run(tmp.path(), &docs, &queries)?;
    report_backend(&fts5_report);

    println!("\n--- 构建并评测 Tantivy ---");
    let tantivy_report = tantivy_be::run(tmp.path(), &docs, &queries)?;
    report_backend(&tantivy_report);

    print_comparison(&fts5_report, &tantivy_report);

    Ok(())
}

fn print_environment(n: usize) {
    println!("环境记录（基准报告必填）：");
    println!("  os            = {}", std::env::consts::OS);
    println!("  arch          = {}", std::env::consts::ARCH);
    println!(
        "  target        = {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!("  sqlite_version= {}", rusqlite::version());
    println!("  doc_count     = {}", n);
    println!("  状态          = 冷构建（每次全新临时目录）");
}

fn report_backend(r: &BackendReport) {
    println!(
        "  构建耗时      = {} ms",
        r.build_ms
    );
    println!(
        "  索引体积      = {} bytes ({:.2} MB)",
        r.index_bytes,
        r.index_bytes as f64 / 1_048_576.0
    );
    println!("  recall@10:");
    for (name, recall) in &r.recalls {
        println!("    {:<40} {:.3}", name, recall);
    }
    println!("  查询延迟:");
    for (name, us) in &r.query_latencies_us {
        println!("    {:<40} {} µs", name, us);
    }
    println!("  平均 recall@10 = {:.3}", r.mean_recall());
    println!("  最大查询延迟   = {} µs", r.p_latency_us());
}

fn print_comparison(fts5: &BackendReport, tantivy: &BackendReport) {
    println!("\n=== Selection Gate 对照汇总 ===");
    println!(
        "{:<16} {:>14} {:>16} {:>16} {:>16}",
        "backend", "mean_recall@10", "index_MB", "build_ms", "max_query_µs"
    );
    for r in [fts5, tantivy] {
        println!(
            "{:<16} {:>14.3} {:>16.2} {:>16} {:>16}",
            r.name,
            r.mean_recall(),
            r.index_bytes as f64 / 1_048_576.0,
            r.build_ms,
            r.p_latency_us()
        );
    }

    println!("\nADR-0001 决策证据：");
    let recall_gap = fts5.mean_recall() - tantivy.mean_recall();
    let size_ratio = if fts5.index_bytes > 0 {
        tantivy.index_bytes as f64 / fts5.index_bytes as f64
    } else {
        0.0
    };
    println!("  recall 差 (FTS5 - Tantivy) = {:.3}", recall_gap);
    println!("  索引体积比 (Tantivy / FTS5) = {:.2}x", size_ratio);
    println!(
        "  结论倾向：{}",
        if tantivy.mean_recall() > fts5.mean_recall() + 0.05 {
            "Tantivy 在 recall 上有可测量优势，需进一步评估是否值得双存储成本"
        } else {
            "FTS5 未被 Tantivy 明显超越 → 维持 FTS5 单存储默认（更低一致性/运维风险）"
        }
    );
    println!("\n注意：本结论为 ADR-0001 的 Windows x64 初步证据；排序质量、标准语料与其他正式 target 仍待补测。");
}
