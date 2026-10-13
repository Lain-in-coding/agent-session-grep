//! D3 六项不变量自查（adapters-sqlite 层）：#6 投影截断共病（对比 hstry H-01）。
//!
//! 竞品反例：索引、展示、导出共用同一个"截断后正文"投影，于是"搜不到"与
//! "看不到"同时发生，产品却仍声称全文可检索。
//!
//! ASG 侧的落地事实（本文件用可执行断言钉住）：
//! - FTS 投影有界：`searchable_text`/`bounded_index_text` 把单条消息的索引
//!   正文截断到 [`MESSAGE_FTS_MAX_CHARS`]（`agent-session-grep-adapters-sqlite/
//!   src/lib.rs:168-200`，16,000 字符，文档披露见
//!   `docs/release/go-no-go.2026-08-16.md:631`）；
//! - catalog 保留 provider 原文全文（THREAT-MODEL：索引期不改写原文），
//!   `get`/`show`（及 context/handoff 装配）读 catalog；产品当前无独立导出命令，不共用截断投影；
//! - 写入路径（commit 三元组，CLI 以 `bounded_index_text` 构造）与 rebuild
//!   路径（从 catalog payload 重新投影）必须产出同一有界结果，否则 current
//!   判定两侧分叉（`src/lib.rs:176-179`）。
//!
//! 诚实口径：超出上限的词不可检索是**有界投影**的已知语义，不是"全文可
//! 检索"的缺陷；边界记录（README 的 "full-text search" 措辞未带 16k 限定）
//! 见 research/invariant-matrix.md 第 6 项。

use agent_session_grep_adapters_sqlite::SqliteStore;
use agent_session_grep_application::{
    App, AppRequest, AppResponse, MESSAGE_FTS_MAX_CHARS, ResponseBudget, bounded_index_text,
};
use agent_session_grep_domain::{IdKind, StableId};
use agent_session_grep_ports::{
    CatalogStore, NoResumeClaims, RetrievalMode, SearchFacets, SearchFilters, SearchIndex,
};

fn sid(tag: &str) -> StableId {
    StableId::native(IdKind::Message, tag)
}

/// 超过索引上限的消息正文：`headneedle` 落在上限内，`tailneedle` 落在上限后。
fn long_body() -> String {
    let head = format!("headneedle {}", "filler".repeat(MESSAGE_FTS_MAX_CHARS / 6));
    let full = format!("{head} tailneedle");
    assert!(
        full.chars().count() > MESSAGE_FTS_MAX_CHARS,
        "fixture must exceed the FTS projection cap"
    );
    full
}

fn payload(full: &str) -> Vec<u8> {
    serde_json::json!({
        "role": "user",
        "text": full,
        "timestamp": "2026-08-24T00:00:00Z",
    })
    .to_string()
    .into_bytes()
}

#[test]
fn capped_projection_is_identical_across_write_and_rebuild_paths() {
    let store = SqliteStore::open_in_memory().unwrap();
    let id = sid("projection-message");
    let full = long_body();

    // 生产形状（CLI sync 构造三元组）：catalog payload 全文 + FTS 投影有界。
    let entries = [(id.clone(), payload(&full), bounded_index_text(&full))];
    assert!(store.commit_batch_if_changed(&entries).unwrap());

    assert_eq!(store.query("headneedle", 10).unwrap().len(), 1);
    assert!(
        store.query("tailneedle", 10).unwrap().is_empty(),
        "terms beyond the capped projection must not be indexed"
    );
    let stored = store.get(&id).unwrap().unwrap();
    assert!(
        String::from_utf8_lossy(&stored).contains("tailneedle"),
        "catalog must keep the full provider text"
    );

    // rebuild 从 catalog 权威出处重新投影：有界语义必须与写入路径逐点一致，
    // 否则 current 判定两侧分叉、重同步反复推进 generation。
    store.rebuild_index().unwrap();
    assert_eq!(store.query("headneedle", 10).unwrap().len(), 1);
    assert!(
        store.query("tailneedle", 10).unwrap().is_empty(),
        "rebuild must not widen or drop the cap"
    );
    let stored_after = store.get(&id).unwrap().unwrap();
    assert!(
        String::from_utf8_lossy(&stored_after).contains("tailneedle"),
        "rebuild must not rewrite the authoritative full-text payload"
    );
}

#[test]
fn app_get_returns_full_body_while_search_stays_inside_the_projection() {
    let store = SqliteStore::open_in_memory().unwrap();
    let id = sid("projection-app-message");
    let full = long_body();
    let entries = [(id.clone(), payload(&full), bounded_index_text(&full))];
    assert!(store.commit_batch_if_changed(&entries).unwrap());

    let app = App::with_resume_semantic(&store, &store, NoResumeClaims, &store);
    for (query, expected_hits) in [("headneedle", 1usize), ("tailneedle", 0usize)] {
        let response = app
            .handle(AppRequest::Search {
                query: query.into(),
                filters: SearchFilters::default(),
                facets: SearchFacets::default(),
                limit: 10,
                cursor: None,
                budget: ResponseBudget::default(),
                include_system: true,
                group_by_session: false,
                mode: RetrievalMode::Lexical,
                query_embedding: None,
            })
            .unwrap();
        let AppResponse::Search { hits, .. } = response else {
            panic!("search expected");
        };
        assert_eq!(
            hits.len(),
            expected_hits,
            "query {query:?} must follow the bounded projection, not the full body"
        );
    }

    // 展示/取回读 catalog：全文照常可取——索引截断没有被扩散成展示/取回截断。
    let response = app.handle(AppRequest::Get { id }).unwrap();
    let AppResponse::Get { payload } = response else {
        panic!("get expected");
    };
    let payload = payload.expect("committed entity must be readable");
    assert!(
        String::from_utf8_lossy(&payload).contains("tailneedle"),
        "get must return the full authoritative body"
    );
}
