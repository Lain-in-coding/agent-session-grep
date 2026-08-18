//! Tantivy 后端（0.26.1，API 参照 fast-resume src/index/）。
//! 索引预分析后的 token 串（用 raw tokenizer，避免 Tantivy 自带分词
//! 与 analyzer 冲突），查询侧用同一 analyzer 产出的 token 做 OR。

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, FAST, STORED,
};
use tantivy::{doc, Index, TantivyDocument, Term};

use crate::analyzer::analyze;
use crate::corpus::{Doc, QueryCase};
use crate::BackendReport;

struct Fields {
    id: Field,
    provider: Field,
    title: Field,
    body: Field,
    title_idx: Field,
    body_idx: Field,
}

fn build_schema() -> (Schema, Fields) {
    let mut builder = Schema::builder();
    // id 存 u64 fast，便于取回
    let id = builder.add_u64_field("id", STORED | FAST);
    // 原文字段 STORED 但不索引——与 FTS5 一样保留原文，保证体积对比公平
    // （两个引擎都存 原文 + 预分析索引）。
    let provider = builder.add_text_field("provider", STORED);
    let title = builder.add_text_field("title", STORED);
    let body = builder.add_text_field("body", STORED);
    // 预分析 token 串用 whitespace_lower：只按空格切 + lowercase（token 已 lowercase），
    // 不 STORED，只索引。
    let text_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("whitespace_lower")
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );
    let title_idx = builder.add_text_field("title_idx", text_opts.clone());
    let body_idx = builder.add_text_field("body_idx", text_opts);
    let schema = builder.build();
    (schema, Fields { id, provider, title, body, title_idx, body_idx })
}

pub fn run(dir: &Path, docs: &[Doc], queries: &[QueryCase]) -> Result<BackendReport> {
    let idx_dir = dir.join("tantivy");
    let _ = std::fs::remove_dir_all(&idx_dir);
    std::fs::create_dir_all(&idx_dir)?;

    let (schema, fields) = build_schema();
    let index = Index::create_in_dir(&idx_dir, schema)?;

    // 注册自定义 tokenizer：仅按空格切 + lowercase（token 已 lowercase）。
    use tantivy::tokenizer::{LowerCaser, TextAnalyzer, WhitespaceTokenizer};
    let analyzer = TextAnalyzer::builder(WhitespaceTokenizer::default())
        .filter(LowerCaser)
        .build();
    index.tokenizers().register("whitespace_lower", analyzer);

    let build_start = Instant::now();
    let mut writer = index.writer(50_000_000)?;
    for d in docs {
        let title_tokens = analyze(&d.title).join(" ");
        let body_tokens = analyze(&d.body).join(" ");
        writer.add_document(doc!(
            fields.id => d.id,
            fields.provider => d.provider.clone(),
            fields.title => d.title.clone(),
            fields.body => d.body.clone(),
            fields.title_idx => title_tokens,
            fields.body_idx => body_tokens,
        ))?;
    }
    writer.commit()?;
    let build_ms = build_start.elapsed().as_millis();

    let reader = index.reader()?;
    let searcher = reader.searcher();

    let mut recalls = Vec::new();
    let mut query_latencies_us = Vec::new();
    for q in queries {
        let tokens = analyze(&q.query);
        let query = build_or_query(&fields, &tokens);

        let start = Instant::now();
        let top = searcher.search(&query, &TopDocs::with_limit(10).order_by_score())?;
        let mut ids = Vec::new();
        for (_score, addr) in top {
            let doc: TantivyDocument = searcher.doc(addr)?;
            if let Some(v) = doc.get_first(fields.id) {
                if let Some(id) = v.as_u64() {
                    ids.push(id);
                }
            }
        }
        let elapsed_us = start.elapsed().as_micros();
        query_latencies_us.push((q.name.clone(), elapsed_us));

        let recall = recall_at_10(&ids, &q.relevant);
        recalls.push((q.name.clone(), recall));
    }

    let index_bytes = dir_size(&idx_dir)?;
    Ok(BackendReport {
        name: "Tantivy".to_string(),
        build_ms,
        index_bytes,
        recalls,
        query_latencies_us,
    })
}

fn build_or_query(fields: &Fields, tokens: &[String]) -> BooleanQuery {
    let mut parts: Vec<(Occur, Box<dyn Query>)> = Vec::new();
    for t in tokens {
        let tl = t.to_lowercase();
        let title_term = Term::from_field_text(fields.title_idx, &tl);
        let body_term = Term::from_field_text(fields.body_idx, &tl);
        parts.push((
            Occur::Should,
            Box::new(TermQuery::new(title_term, IndexRecordOption::WithFreqs)),
        ));
        parts.push((
            Occur::Should,
            Box::new(TermQuery::new(body_term, IndexRecordOption::WithFreqs)),
        ));
    }
    BooleanQuery::new(parts)
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
            total += meta.len();
        }
    }
    Ok(total)
}
