//! D3 六项不变量自查（application 层）：#1 cap 先于过滤、#2 零证据升格。
//!
//! 合成端口按端口契约实现检索：**先应用 filters，再排序，最后 LIMIT**——与
//! SQLite adapter 的 `WHERE ... AND <predicates> ... ORDER BY ... LIMIT`
//! （`agent-session-grep-adapters-sqlite/src/lib.rs:7973-7987`）同形。SQL 级
//! pushdown 另有 adapter 既有测试
//! `filtered_predicates_apply_before_limit_in_one_statement` 与
//! `semantic_and_hybrid_apply_provider_time_repo_and_facets_before_limit`
//! 直接锚定；本文件锚定 Application 侧的取数窗口、重排与分页建立在"过滤后
//! 集合"之上，且 boost 只能在已准入命中上重排、绝不引入候选。
//!
//! 证据均为合成数据、注入时钟，不依赖网络/真实用户数据/系统时间。

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use agent_session_grep_application::ranking::final_score;
use agent_session_grep_application::{App, AppRequest, AppResponse, ResponseBudget};
use agent_session_grep_domain::{IdKind, StableId};
use agent_session_grep_ports::{
    CatalogEntry, CatalogStore, ContextGraphStore, ContextStats, MessageContextCandidate,
    NoResumeClaims, PortError, PortResult, RetrievalMode, SearchFacets, SearchFilters, SearchHit,
    SearchIndex, SearchProvider, SearchQuery, SemanticIndex, SourcePlacement,
};

/// 固定应用时钟（2026-08-25T00:00:00Z 的 Unix 毫秒）。
const CLOCK_MS: i64 = 1_787_616_000_000;

fn clock() -> i64 {
    CLOCK_MS
}

fn message_id(tag: &str) -> StableId {
    StableId::native(IdKind::Message, tag)
}

fn session_id(tag: &str) -> StableId {
    StableId::native(IdKind::Session, tag)
}

#[derive(Clone)]
struct Row {
    id: StableId,
    provider: &'static str,
    text: String,
    /// lexical 相关性（模拟 FTS rank 分；MATCH 命中恒为正）。
    score: f32,
    /// 查询向量 [1.0, 0.0] 下的模拟语义向量。
    vector: [f32; 2],
    system: bool,
}

/// `FakeStore::add` 的参数束：避免 9 参函数，同时让 fixture 逐行自解释。
struct RowSpec<'a> {
    id: StableId,
    provider: &'static str,
    text: &'a str,
    score: f32,
    vector: [f32; 2],
    timestamp: &'a str,
    session: &'a StableId,
    repo: Option<&'a str>,
}

#[derive(Default)]
struct Calls {
    lexical_filters: Vec<Vec<String>>,
    semantic_filters: Vec<Vec<String>>,
    lexical_limits: Vec<usize>,
    semantic_limits: Vec<usize>,
}

struct FakeStore {
    rows: Vec<Row>,
    payloads: BTreeMap<String, Vec<u8>>,
    session_by_message: BTreeMap<String, String>,
    repo_by_session: BTreeMap<String, String>,
    calls: Rc<RefCell<Calls>>,
    generation: u64,
}

impl FakeStore {
    fn empty(calls: Rc<RefCell<Calls>>) -> Self {
        Self {
            rows: Vec::new(),
            payloads: BTreeMap::new(),
            session_by_message: BTreeMap::new(),
            repo_by_session: BTreeMap::new(),
            calls,
            generation: 1,
        }
    }

    fn add(&mut self, spec: RowSpec<'_>) {
        self.rows.push(Row {
            id: spec.id.clone(),
            provider: spec.provider,
            text: spec.text.to_string(),
            score: spec.score,
            vector: spec.vector,
            system: false,
        });
        self.payloads.insert(
            spec.id.as_str().to_string(),
            serde_json::json!({
                "role": "user",
                "text": spec.text,
                "timestamp": spec.timestamp,
            })
            .to_string()
            .into_bytes(),
        );
        self.session_by_message.insert(
            spec.id.as_str().to_string(),
            spec.session.as_str().to_string(),
        );
        if let Some(repo) = spec.repo {
            self.repo_by_session
                .insert(spec.session.as_str().to_string(), repo.to_string());
        }
    }

    fn provider_names(filters: &SearchFilters) -> Vec<String> {
        filters
            .providers
            .iter()
            .map(|provider| provider.as_str().to_string())
            .collect()
    }

    fn lexical_hits(
        &self,
        text: &str,
        filters: &SearchFilters,
        limit: usize,
        include_system: bool,
    ) -> Vec<SearchHit> {
        self.calls
            .borrow_mut()
            .lexical_filters
            .push(Self::provider_names(filters));
        self.calls.borrow_mut().lexical_limits.push(limit);
        let mut hits: Vec<SearchHit> = self
            .rows
            .iter()
            // 证据门：只有正文含查询词的候选才存在（FTS MATCH 同义）。
            .filter(|row| row.text.contains(text))
            // 过滤在 cap 之前：provider 维度先收窄候选集，再排序取前 limit。
            .filter(|row| {
                filters.providers.is_empty()
                    || filters
                        .providers
                        .iter()
                        .any(|provider| provider.as_str() == row.provider)
            })
            .filter(|row| include_system || !row.system)
            .map(|row| SearchHit {
                id: row.id.clone(),
                score: row.score,
                session_id: None,
                text: None,
                why_matched: Vec::new(),
                suggested_next_commands: Vec::new(),
                occurrences: 1,
                resume_available: false,
            })
            .collect();
        hits.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.id.as_str().cmp(b.id.as_str()))
        });
        hits.truncate(limit);
        hits
    }
}

impl CatalogStore for FakeStore {
    fn get(&self, id: &StableId) -> PortResult<Option<Vec<u8>>> {
        Ok(self.payloads.get(id.as_str()).cloned())
    }

    fn get_many(&self, ids: &[StableId]) -> PortResult<Vec<(StableId, Option<Vec<u8>>)>> {
        Ok(ids
            .iter()
            .map(|id| (id.clone(), self.payloads.get(id.as_str()).cloned()))
            .collect())
    }

    fn put(&self, _id: &StableId, _payload: &[u8]) -> PortResult<()> {
        Ok(())
    }

    fn list(&self, limit: usize) -> PortResult<Vec<CatalogEntry>> {
        Ok(self
            .payloads
            .iter()
            .take(limit)
            .filter_map(|(wire, payload)| {
                StableId::from_wire(wire).map(|id| CatalogEntry {
                    id,
                    payload: payload.clone(),
                })
            })
            .collect())
    }

    fn list_sessions(&self, _limit: usize) -> PortResult<Vec<CatalogEntry>> {
        Ok(Vec::new())
    }

    fn session_repo_slugs(&self, session_ids: &[StableId]) -> PortResult<Vec<Option<String>>> {
        Ok(session_ids
            .iter()
            .map(|id| self.repo_by_session.get(id.as_str()).cloned())
            .collect())
    }

    fn count(&self) -> PortResult<u64> {
        Ok(self.payloads.len() as u64)
    }

    fn active_generation(&self) -> PortResult<u64> {
        Ok(self.generation)
    }
}

impl ContextGraphStore for FakeStore {
    fn load_session_graph(
        &self,
        _session_id: &StableId,
    ) -> PortResult<agent_session_grep_domain::SessionContextGraph> {
        Err(PortError::NotFound(
            "synthetic catalog has no context graph".into(),
        ))
    }

    fn message_contexts(&self, _message_id: &StableId) -> PortResult<Vec<MessageContextCandidate>> {
        Err(PortError::NotFound(
            "synthetic catalog has no context graph".into(),
        ))
    }

    fn session_of(
        &self,
        message_ids: &[StableId],
    ) -> PortResult<Vec<(StableId, Option<StableId>)>> {
        Ok(message_ids
            .iter()
            .map(|id| {
                let session = self
                    .session_by_message
                    .get(id.as_str())
                    .and_then(|wire| StableId::from_wire(wire));
                (id.clone(), session)
            })
            .collect())
    }

    fn source_placements_of(
        &self,
        message_ids: &[StableId],
    ) -> PortResult<Vec<(StableId, Option<SourcePlacement>)>> {
        Ok(message_ids.iter().map(|id| (id.clone(), None)).collect())
    }

    fn context_stats(&self) -> PortResult<ContextStats> {
        Ok(ContextStats::default())
    }
}

impl SearchIndex for FakeStore {
    fn index(&self, _id: &StableId, _text: &str) -> PortResult<()> {
        Ok(())
    }

    fn query_filtered(&self, query: SearchQuery<'_>, limit: usize) -> PortResult<Vec<SearchHit>> {
        Ok(self.lexical_hits(query.text, query.filters, limit, true))
    }

    fn query_with_policy(
        &self,
        query: SearchQuery<'_>,
        limit: usize,
        _facets: &SearchFacets,
        include_system: bool,
    ) -> PortResult<Vec<SearchHit>> {
        Ok(self.lexical_hits(query.text, query.filters, limit, include_system))
    }
}

impl SemanticIndex for FakeStore {
    fn index_embedding(&self, _id: &StableId, _embedding: &[f32]) -> PortResult<()> {
        Ok(())
    }

    fn query_semantic_filtered(
        &self,
        query_embedding: &[f32],
        limit: usize,
        filters: &SearchFilters,
        _facets: &SearchFacets,
        include_system: bool,
    ) -> PortResult<Vec<SearchHit>> {
        self.calls
            .borrow_mut()
            .semantic_filters
            .push(Self::provider_names(filters));
        self.calls.borrow_mut().semantic_limits.push(limit);
        let mut scored: Vec<(f32, &Row)> = self
            .rows
            .iter()
            // 过滤在 top-k 之前（与 adapter 的 SQL 谓词 + Rust 侧 top-k 同形）。
            .filter(|row| {
                filters.providers.is_empty()
                    || filters
                        .providers
                        .iter()
                        .any(|provider| provider.as_str() == row.provider)
            })
            .filter(|row| include_system || !row.system)
            .map(|row| (cosine(query_embedding, &row.vector), row))
            .collect();
        scored.sort_by(|a, b| {
            b.0.total_cmp(&a.0)
                .then_with(|| a.1.id.as_str().cmp(b.1.id.as_str()))
        });
        Ok(scored
            .into_iter()
            .take(limit)
            .map(|(score, row)| SearchHit {
                id: row.id.clone(),
                score,
                session_id: None,
                text: None,
                why_matched: Vec::new(),
                suggested_next_commands: Vec::new(),
                occurrences: 1,
                resume_available: false,
            })
            .collect())
    }

    fn is_ready(&self) -> PortResult<bool> {
        Ok(true)
    }

    fn semantic_model_id(&self) -> PortResult<Option<String>> {
        Ok(Some("invariant-model".into()))
    }
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

fn search(
    app: &App<&FakeStore, &FakeStore, NoResumeClaims, &FakeStore>,
    query: &str,
    filters: SearchFilters,
    limit: usize,
    mode: RetrievalMode,
) -> (Vec<StableId>, Option<String>) {
    let response = app
        .handle(AppRequest::Search {
            query: query.into(),
            filters,
            facets: SearchFacets::default(),
            limit,
            cursor: None,
            budget: ResponseBudget::default(),
            include_system: true,
            group_by_session: false,
            mode,
            query_embedding: Some(vec![1.0, 0.0]),
        })
        .expect("synthetic search must succeed");
    let AppResponse::Search {
        hits, next_cursor, ..
    } = response
    else {
        panic!("search expected");
    };
    (hits.into_iter().map(|hit| hit.id).collect(), next_cursor)
}

fn codex_only() -> SearchFilters {
    SearchFilters {
        providers: vec![SearchProvider::Codex],
        ..SearchFilters::default()
    }
}

/// 域外（claude）候选以显著更高的相关性占满 cap 窗口，域内（codex）仍有合法命中。
fn cap_corpus() -> (Rc<RefCell<Calls>>, FakeStore) {
    let calls = Rc::new(RefCell::new(Calls::default()));
    let mut store = FakeStore::empty(calls.clone());
    for i in 0..40 {
        let id = message_id(&format!("out-of-domain-{i:03}"));
        store.add(RowSpec {
            id,
            provider: "claude-code",
            text: "cap-token shared body",
            score: 9.0,
            vector: [1.0, 0.0],
            timestamp: "2026-08-24T00:00:00Z",
            session: &session_id("ses-out"),
            repo: None,
        });
    }
    for i in 0..2 {
        let id = message_id(&format!("in-domain-{i}"));
        store.add(RowSpec {
            id,
            provider: "codex",
            text: "cap-token shared body",
            score: 1.0,
            vector: [0.8, 0.6],
            timestamp: "2026-08-24T00:00:00Z",
            session: &session_id(&format!("ses-in-{i}")),
            repo: None,
        });
    }
    (calls, store)
}

#[test]
fn provider_filter_precedes_the_cap_in_lexical_semantic_and_hybrid_paths() {
    let (calls, store) = cap_corpus();
    let app = App::with_resume_semantic_and_clock(&store, &store, NoResumeClaims, &store, clock);

    for mode in [
        RetrievalMode::Lexical,
        RetrievalMode::Semantic,
        RetrievalMode::Hybrid,
    ] {
        let (ids, cursor) = search(&app, "cap-token", codex_only(), 2, mode);
        assert!(
            ids.iter()
                .all(|id| id.as_str().starts_with("msg_v1_in-domain-")),
            "mode {mode:?} admitted out-of-domain hits: {ids:?}"
        );
        assert_eq!(ids.len(), 2, "mode {mode:?} lost in-domain hits: {ids:?}");
        assert!(cursor.is_none(), "two in-domain rows fit one page");
    }

    let calls = calls.borrow();
    assert!(
        calls
            .lexical_filters
            .iter()
            .all(|providers| providers == &vec!["codex".to_string()]),
        "lexical retrieval must carry the provider predicate: {:?}",
        calls.lexical_filters
    );
    assert!(
        calls
            .semantic_filters
            .iter()
            .all(|providers| providers == &vec!["codex".to_string()]),
        "semantic retrieval must carry the provider predicate: {:?}",
        calls.semantic_filters
    );
    // 取数窗口按页+哨兵要求发出，绝不被域外候选挤掉（窗口 > 域内命中数）。
    assert!(calls.lexical_limits.iter().all(|limit| *limit >= 2));
    assert!(calls.semantic_limits.iter().all(|limit| *limit >= 2));
}

#[test]
fn zero_evidence_recent_repo_candidate_is_not_admitted_by_boost() {
    let calls = Rc::new(RefCell::new(Calls::default()));
    let mut store = FakeStore::empty(calls);
    let repo = "example.test/team/repo";
    let session = session_id("ses-evidence");
    // 零证据候选：时间最新、属于当前 repo，但正文不含查询词、向量与查询正交
    // （lexical/语义证据均为零）——不得进入 lexical 结果。
    store.add(RowSpec {
        id: message_id("zero-evidence-recent"),
        provider: "codex",
        text: "unrelated envelope text",
        score: 9.0,
        vector: [0.0, 1.0],
        timestamp: "2026-08-25T00:00:00Z",
        session: &session,
        repo: Some(repo),
    });
    // 有证据候选：新近命中。
    store.add(RowSpec {
        id: message_id("matching-recent"),
        provider: "codex",
        text: "invariant-needle body",
        score: 1.0,
        vector: [1.0, 0.0],
        timestamp: "2026-08-24T00:00:00Z",
        session: &session,
        repo: Some(repo),
    });
    // 有证据候选：老命中（用于证明 boost 确实在已准入命中上重排）。
    store.add(RowSpec {
        id: message_id("matching-old"),
        provider: "codex",
        text: "invariant-needle body",
        score: 1.0,
        vector: [1.0, 0.0],
        timestamp: "2020-01-01T00:00:00Z",
        session: &session,
        repo: Some(repo),
    });
    let app = App::with_resume_semantic_and_clock(&store, &store, NoResumeClaims, &store, clock)
        .with_current_repo(Some(repo.to_string()));

    // 只在 lexical 路径做准入断言：该路径的证据门是正文命中（FTS MATCH）。
    // Semantic/Hybrid 的证据定义是向量相似度，adapter 的 top-k 无相似度阈值
    // （见 research/invariant-matrix.md 第 2 项边界记录）——不在此冒充已通过。
    let (ids, _) = search(
        &app,
        "invariant-needle",
        SearchFilters::default(),
        10,
        RetrievalMode::Lexical,
    );
    assert_eq!(
        ids.iter().map(StableId::as_str).collect::<Vec<_>>(),
        vec!["msg_v1_matching-recent", "msg_v1_matching-old",],
        "evidence gate must exclude the recent repo candidate and \
         recency must order the admitted hits"
    );

    // ranking 层的同口径断言：近因/repo 是加在已准入相关性上的信号，
    // 只能放大正相关证据，不能把"无候选"变成候选（准入由检索端口决定）。
    let recent = final_score(1.0, 0, false, true);
    let old = final_score(1.0, i64::MAX / 2, false, true);
    assert!(recent > old, "recency signal must re-order admitted hits");
    assert!(old > 0.0, "repo boost keeps admitted evidence positive");
}
