//! 合成语料 + qrels（遵循 Fixture 脱敏规范，禁止使用真实 transcript）。
//! 生成可复现的多语言会话文档，并为一组 query 标注已知相关文档，
//! 用于计算 recall@10。种子固定，保证跨运行/跨引擎一致。
//!
//! 方法论：beacon 标记词只注入 beacon 文档，绝不出现在随机填充池中，
//! 因此 qrels 干净，recall@10 有区分度；两个引擎吃同一套 (docs, queries)。

use std::collections::BTreeSet;

/// 一条合成会话文档。
#[derive(Clone, Debug)]
pub struct Doc {
    pub id: u64,
    pub provider: String,
    pub title: String,
    pub body: String,
}

/// 一条评测查询及其相关文档 id 集合。
#[derive(Clone, Debug)]
pub struct QueryCase {
    pub name: String,
    pub query: String,
    pub relevant: BTreeSet<u64>,
}

/// 极简可复现 PRNG（xorshift64），避免引入 rand 依赖。
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        let i = (self.next() % xs.len() as u64) as usize;
        &xs[i]
    }
}

const PROVIDERS: &[&str] = &["claude-code", "codex", "cursor", "codebuddy", "pi"];

// 随机填充池——刻意不含任何 beacon 查询词，避免污染 qrels。
const ZH_FILLER: &[&str] = &[
    "增量同步", "崩溃恢复", "分支合并", "数据迁移", "缓存失效",
    "并发控制", "权限校验", "路径解析", "会话归档", "内容去重",
    "跨平台构建", "签名验证", "供应链安全", "只读快照", "生成切换",
];
const CODE_FILLER: &[&str] = &[
    "SourceDocument", "GenerationBundle", "ReadOnlySourceSnapshot",
    "writer_lease", "operation_digest", "cursor_token", "tokio::spawn",
    "serde_json::from_str", "BLAKE3", "IndexWriter",
];
const PATH_FILLER: &[&str] = &[
    "src/db/schema.rs", "crates/agent-session-grep-storage/src/lib.rs",
    "C:\\Users\\dev\\project\\main.rs", "/home/user/.codex/sessions/2026/07",
    "docs/architecture/rfc-0001.md", "src/adapters/claude.rs",
];
const EN_FILLER: &[&str] = &[
    "incremental sync must be idempotent across repeated runs",
    "the writer lease prevents two processes from racing generations",
    "external content table with triggers keeps rank stable",
    "a generation bundle is an immutable snapshot on disk",
    "the catalog is the canonical source of truth for search",
];
const ERR_FILLER: &[&str] = &[
    "thread 'main' panicked at 'called Result::unwrap() on an Err value'",
    "error[E0499]: cannot borrow `x` as mutable more than once",
    "SQLITE_BUSY: database is locked",
    "index out of bounds: the len is 0 but the index is 3",
];

// Beacon 标记——只出现在 beacon 文档中，作为干净的 qrels 锚点。
const BEACON_ZH_TITLE: &str = "架构决策：索引重建策略与不可变代际";
const BEACON_ZH_BODY: &str = "我们决定在索引重建时采用不可变 generation bundle，避免原地修改活动目录。";
const BEACON_CODE_BODY: &str = "fn normalizeProjectPath(p: &Path) -> PathBuf { normalize_case_and_sep(p) }";
const BEACON_PATH_BODY: &str = "堆栈最终指向 src/adapters/cursor.rs 的路径归一化逻辑。";
const BEACON_EN_BODY: &str = "We apply reciprocal rank fusion to merge lexical and semantic candidates.";
const BEACON_ERR_BODY: &str = "运行时抛出 BorrowMutError，重复可变借用触发了 panic。";

/// 生成 `n` 篇文档 + 若干带 qrels 的查询。
pub fn build(n: usize) -> (Vec<Doc>, Vec<QueryCase>) {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut docs = Vec::with_capacity(n);

    let mut beacon_zh = BTreeSet::new();
    let mut beacon_code = BTreeSet::new();
    let mut beacon_path = BTreeSet::new();
    let mut beacon_en = BTreeSet::new();
    let mut beacon_err = BTreeSet::new();

    for id in 0..n as u64 {
        let provider = PROVIDERS[(id as usize) % PROVIDERS.len()].to_string();
        let zh = rng.pick(ZH_FILLER);
        let code = rng.pick(CODE_FILLER);
        let path = rng.pick(PATH_FILLER);
        let en = rng.pick(EN_FILLER);
        let err = rng.pick(ERR_FILLER);

        let mut title = format!("{zh} - {code}");
        let mut body = format!(
            "讨论 {zh} 的实现方案。相关代码 {code} 位于 {path}。\n{en}\n遇到报错：{err}",
        );

        // 注入 beacon：不同步长，保证各类 qrels 都有稳定基数（约 20-50 篇）。
        if id % 37 == 0 {
            title = BEACON_ZH_TITLE.to_string();
            body.push('\n');
            body.push_str(BEACON_ZH_BODY);
            beacon_zh.insert(id);
        }
        if id % 41 == 0 {
            body.push('\n');
            body.push_str(BEACON_CODE_BODY);
            beacon_code.insert(id);
        }
        if id % 43 == 0 {
            body.push('\n');
            body.push_str(BEACON_PATH_BODY);
            beacon_path.insert(id);
        }
        if id % 47 == 0 {
            body.push('\n');
            body.push_str(BEACON_EN_BODY);
            beacon_en.insert(id);
        }
        if id % 53 == 0 {
            body.push('\n');
            body.push_str(BEACON_ERR_BODY);
            beacon_err.insert(id);
        }

        docs.push(Doc { id, provider, title, body });
    }

    let queries = vec![
        QueryCase { name: "中文术语(索引重建)".into(), query: "索引重建".into(), relevant: beacon_zh },
        QueryCase { name: "代码标识符(normalizeProjectPath)".into(), query: "normalizeProjectPath".into(), relevant: beacon_code },
        QueryCase { name: "路径(cursor.rs)".into(), query: "cursor.rs".into(), relevant: beacon_path },
        QueryCase { name: "英文短语(reciprocal rank fusion)".into(), query: "reciprocal rank fusion".into(), relevant: beacon_en },
        QueryCase { name: "错误标识(BorrowMutError)".into(), query: "BorrowMutError".into(), relevant: beacon_err },
    ];

    (docs, queries)
}
