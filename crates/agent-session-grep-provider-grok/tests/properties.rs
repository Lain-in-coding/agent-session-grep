//! Grok Build adapter（`grok-build/acp-updates-v1`）的确定性 property 套件。
//!
//! 用固定种子生成随机 ACP `session/update` 流（chunk 分组 / rewind 截断 /
//! bash 元块 / 未知 kind 噪声 / 坏行 / 混合行尾），逐条验证结构不变量：
//!
//! 1. span 回切：每条消息的 span 切回快照字节等于其首个 chunk 的源行（去行尾）；
//! 2. seq 从 0 连续，committed == emit 数 == ground truth 消息数；
//! 3. 确定性：同一字节两次解析，事件流与报告完全一致；
//! 4. 元数据透传：role/text 原样、native_id 恒空、无 parent/timestamp/sidechain；
//! 5. 会话身份：session_native_id 等于首个 agent promptId，multi_session 与 ground truth 一致；
//! 6. 坏行只递增 skipped/diagnostics，绝不吞消息、绝不中止解析。
//!
//! 另有两个 fuzz 面（同一固定种子纪律）：
//! - probe 对任意字节（纯随机 / 随机文本 / JSON 状行 / golden 截断）永不 panic；
//!   Ok 时 confidence 绝不 Ambiguous（RFC-0002 §3 歧义即拒绝）且 variant 恒为自身；
//! - golden fixture 的 seeded 确定性变异（截断 / 插入 / 删除 / 翻转 / 拆行 / 乱序行）
//!   下 parse 永不 panic：Ok 则消息字段合法（span 界内且回切源行、committed==emit、
//!   正文非空、chunk 种类与角色一致），Err 则 recoverable 由上层回滚；变异源字节
//!   前后不变（RFC-0002 §7 只读契约，经 testkit `assert_read_only` 守护）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表；断言信息一律携带
//! seed，失败可用该 seed 单独重放；不落盘、不联网。

use std::panic::{AssertUnwindSafe, catch_unwind};

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_grok::GrokBuildAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::{Value, json};

const VARIANT_ID: &str = "grok-build/acp-updates-v1";
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.jsonl");

/// 收集 emit 的消息事件；派生 PartialEq 以支撑"两次解析逐字段一致"断言。
#[derive(Default)]
struct CollectingSink {
    messages: Vec<Captured>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Captured {
    seq: u32,
    native_id: String,
    parent_native_id: Option<String>,
    role: String,
    text: String,
    timestamp: Option<String>,
    is_sidechain: bool,
    span: Option<(u64, u64)>,
}

impl CanonicalEventSink for CollectingSink {
    fn emit_message(
        &mut self,
        event: MessageEvent<'_>,
    ) -> agent_session_grep_ports::PortResult<()> {
        self.messages.push(Captured {
            seq: event.seq,
            native_id: event.native_id.to_string(),
            parent_native_id: event.parent_native_id.map(str::to_string),
            role: event.role.to_string(),
            text: event.text.to_string(),
            timestamp: event.timestamp.map(str::to_string),
            is_sidechain: event.is_sidechain,
            span: event.span,
        });
        Ok(())
    }
}

/// xorshift64*（Marsaglia 2003）：十几行的确定性 PRNG，避免引入随机数依赖。
struct XorShift64Star(u64);

impl XorShift64Star {
    fn new(seed: u64) -> Self {
        // 0 是 xorshift 的不动点，换成任意固定非零常量。
        XorShift64Star(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// 均匀取 `[0, n)`；n 必须 > 0。取模偏差对测试生成器无关紧要。
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// 以 num/den 概率返回 true。
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.next_u64() % den < num
    }

    fn pick<'a>(&mut self, pool: &'a [&'a str]) -> &'a str {
        pool[self.below(pool.len())]
    }
}

/// 64 个固定种子：常量步进展开（黄金比例增量），跨平台跨运行完全一致。
fn fixed_seeds() -> [u64; 64] {
    let mut seeds = [0u64; 64];
    let mut acc: u64 = 0x0198_C0DE_5EED_0001;
    for slot in &mut seeds {
        *slot = acc;
        acc = acc.wrapping_add(0x9E37_79B9_7F4A_7C15);
    }
    seeds
}

/// Unicode 文本池：CJK、emoji、RTL（阿拉伯/希伯来）、全角、星面字符与转义敏感片段。
const TEXT_POOL: [&str; 12] = [
    "你好，世界",
    "chunk 分组自检",
    "emoji 🚀😀✅",
    "مرحبا بالعالم",
    "שלום עולם",
    "café Ünïcode",
    "line\nbreak inside",
    "tab\tand \"quotes\" and \\backslash",
    "混合 mixed ASCII 与 CJK",
    "ｆｕｌｌｗｉｄｔｈ　ＡＢＣ",
    "𝔞𝔰𝔱𝔯𝔞𝔩 𝖕𝖑𝖆𝖓𝖊 chars",
    "尾随空格  ",
];

/// 损坏行池：截断 JSON、非 JSON、类型不符——都必须走 record_recoverable 跳过。
const MALFORMED_POOL: [&str; 5] = [
    r#"{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"torn"#,
    "{ not json at all",
    "]]]",
    "\"unterminated string",
    "42 trailing garbage }",
];

/// 一条预期产出的重建消息：角色、累积文本与首个 chunk 的渲染行（span 回切对照物）。
struct ExpectedMessage {
    role: String,
    text: String,
    span_line: String,
}

/// 一个生成的 ACP 流用例：快照字节 + 全部预期值 + 语料覆盖度标志。
struct Case {
    bytes: Vec<u8>,
    expected: Vec<ExpectedMessage>,
    session_id: Option<String>,
    multi_session: bool,
    malformed: usize,
    merged: bool,
    rewind_hit: bool,
    bash_seen: bool,
}

/// chunk 的 content 形态；`text()` 与生产 `grok_content_text` 的抽取结果一致。
enum Content {
    /// 字符串 content。
    Text(String),
    /// `{type:"text", text:...}` 块数组，块间以 `\n` 拼接。
    Blocks(Vec<String>),
    /// bash 元块（`/_meta/bashCommand`）——用户 chunk 直接丢弃并清 pending。
    Bash,
    /// 空 content（`""` / `[]` / `{}` / `null`）——text 为空的无副作用 chunk。
    Empty(Value),
}

impl Content {
    fn text(&self) -> String {
        match self {
            Content::Text(t) => t.clone(),
            Content::Blocks(ts) => ts.join("\n"),
            Content::Bash | Content::Empty(_) => String::new(),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Content::Text(t) => json!(t),
            Content::Blocks(ts) => Value::Array(
                ts.iter()
                    .map(|t| json!({"type": "text", "text": t}))
                    .collect(),
            ),
            Content::Bash => json!({
                "text": "synthetic tool meta",
                "_meta": {"bashCommand": "synthetic"}
            }),
            Content::Empty(v) => v.clone(),
        }
    }
}

/// 流事件；Malformed/Blank 在生成时即携带渲染行（需要 rng 选池）。
enum Event {
    UserChunk { key: Option<u64>, content: Content },
    AgentChunk { key: String, content: Content },
    Rewind { target: u64 },
    Unknown,
    NoUpdate,
    Malformed(String),
    Blank(String),
}

/// 与生产 `parse_source` 同构的状态机仿真：生成器决定事件语义，仿真决定
/// ground truth（哪些 chunk 合并成消息、rewind 截断到哪、会话 id 集合）。
/// 仿真忠实镜像 adapter 的分支顺序（bash 先于 seen_prompt_index 等），
/// 因此"生成器想表达什么"与"adapter 实际会产出什么"由同一份逻辑判定。
struct SimMessage {
    is_user: bool,
    text: String,
    span_line: String,
}

#[derive(Default)]
struct Sim {
    messages: Vec<SimMessage>,
    user_indices: Vec<usize>,
    pending_user: Option<(Option<u64>, usize)>,
    pending_agent: Option<(String, usize)>,
    seen_prompt_index: bool,
    session_ids: Vec<String>,
    skipped: usize,
    merged: bool,
    rewind_hit: bool,
    bash_seen: bool,
}

impl Sim {
    fn run(&mut self, ev: &Event, rendered_line: &str) {
        match ev {
            Event::UserChunk { key, content } => {
                self.pending_agent = None;
                if matches!(content, Content::Bash) {
                    self.pending_user = None;
                    self.bash_seen = true;
                    return;
                }
                let text = content.text();
                if text.is_empty() {
                    return;
                }
                if key.is_some() {
                    self.seen_prompt_index = true;
                }
                let counts_as_user = !self.seen_prompt_index || key.is_some();
                if !counts_as_user {
                    self.pending_user = None;
                    return;
                }
                if let Some((pending_idx, msg_idx)) = &self.pending_user
                    && pending_idx == key
                    && let Some(m) = self.messages.get_mut(*msg_idx)
                    && m.is_user
                {
                    m.text.push_str(&text);
                    self.merged = true;
                    return;
                }
                let msg_idx = self.messages.len();
                self.user_indices.push(msg_idx);
                self.messages.push(SimMessage {
                    is_user: true,
                    text,
                    span_line: rendered_line.to_string(),
                });
                self.pending_user = Some((*key, msg_idx));
            }
            Event::AgentChunk { key, content } => {
                self.pending_user = None;
                let text = content.text();
                if text.trim().is_empty() {
                    return;
                }
                if let Some((pending_id, msg_idx)) = &self.pending_agent
                    && pending_id == key
                    && let Some(m) = self.messages.get_mut(*msg_idx)
                    && !m.is_user
                {
                    m.text.push_str(&text);
                    self.merged = true;
                    return;
                }
                let msg_idx = self.messages.len();
                self.messages.push(SimMessage {
                    is_user: false,
                    text,
                    span_line: rendered_line.to_string(),
                });
                self.pending_agent = Some((key.clone(), msg_idx));
                if !key.is_empty() && !self.session_ids.iter().any(|s| s == key) {
                    self.session_ids.push(key.clone());
                }
            }
            Event::Rewind { target } => {
                if let Some(msg_idx) = self.user_indices.get(*target as usize).copied() {
                    self.messages.truncate(msg_idx);
                    self.user_indices.truncate(*target as usize);
                    self.pending_user = None;
                    self.pending_agent = None;
                    self.rewind_hit = true;
                }
            }
            Event::Unknown | Event::NoUpdate | Event::Blank(_) => {}
            Event::Malformed(_) => self.skipped += 1,
        }
    }
}

fn gen_text(rng: &mut XorShift64Star) -> String {
    let n = 1 + rng.below(3);
    (0..n)
        .map(|_| rng.pick(&TEXT_POOL))
        .collect::<Vec<_>>()
        .join(" ")
}

/// ~256 KiB 大字段：多字节图样重复，压大行路径与 UTF-8 span 计算。
fn big_text() -> String {
    let unit = "大字段填充🚀0123456789abcdef ";
    let mut s = String::with_capacity(262_144 + unit.len());
    while s.len() < 262_144 {
        s.push_str(unit);
    }
    s
}

fn gen_content(rng: &mut XorShift64Star) -> Content {
    match rng.below(10) {
        0..=4 => Content::Text(gen_text(rng)),
        5..=7 => {
            let n = 1 + rng.below(3);
            let texts: Vec<String> = (0..n).map(|_| gen_text(rng)).collect();
            Content::Blocks(texts)
        }
        8 => Content::Empty(match rng.below(4) {
            0 => json!(""),
            1 => json!([]),
            2 => json!({}),
            _ => Value::Null,
        }),
        _ => Content::Empty(Value::Null),
    }
}

fn render_event(ev: &Event) -> String {
    match ev {
        Event::UserChunk { key, content } => {
            let mut record = json!({
                "timestamp": "2026-01-01T00:00:00Z",
                "params": {
                    "update": {"sessionUpdate": "user_message_chunk", "content": content.to_json()}
                }
            });
            if let Some(k) = key {
                record["params"]["_meta"] = json!({"promptIndex": k});
            }
            record.to_string()
        }
        Event::AgentChunk { key, content } => {
            let mut record = json!({
                "params": {
                    "update": {"sessionUpdate": "agent_message_chunk", "content": content.to_json()}
                }
            });
            if !key.is_empty() {
                record["params"]["_meta"] = json!({"promptId": key});
            }
            record.to_string()
        }
        Event::Rewind { target } => json!({
            "params": {
                "update": {"sessionUpdate": "rewind_marker", "targetPromptIndex": target}
            }
        })
        .to_string(),
        Event::Unknown => json!({
            "params": {
                "update": {"sessionUpdate": "summary_chunk", "content": "synthetic non-conversational"}
            }
        })
        .to_string(),
        Event::NoUpdate => json!({"timestamp": "2026-01-01T00:00:00Z", "params": {}}).to_string(),
        Event::Malformed(line) | Event::Blank(line) => line.clone(),
    }
}

fn build_case(seed: u64, with_big_field: bool) -> Case {
    let mut rng = XorShift64Star::new(seed);
    let mut sim = Sim::default();
    let mut rendered: Vec<String> = Vec::new();

    // Agent chunk 配额 0..=4：20% 的种子没有任何 agent chunk，因此也就没有
    // 会话 id（grok 的会话 id 只来自 agent 的 promptId）——保证语料覆盖
    // "有会话 / 无会话"两个分支。
    let n_agent_quota = rng.below(5);
    let mut agents_emitted = 0usize;

    let line_count = 8 + rng.below(28);
    for i in 0..line_count {
        let ev = if with_big_field && i == 0 {
            Event::UserChunk {
                key: Some(0),
                content: Content::Text(big_text()),
            }
        } else {
            let roll = rng.next_u64() % 100;
            if roll < 38 {
                // 用户 chunk：键从 0..=7 的小池里复用（无键 20%），连续同键即合并。
                let key = match rng.below(10) {
                    0..=1 => None,
                    k => Some((k - 2) as u64),
                };
                Event::UserChunk {
                    key,
                    content: gen_content(&mut rng),
                }
            } else if roll < 72 && agents_emitted < n_agent_quota {
                // Agent chunk：空 promptId 20%（不贡献会话 id），其余 p0..=p7。
                agents_emitted += 1;
                let key = match rng.below(10) {
                    0..=1 => String::new(),
                    k => format!("p{}", k - 2),
                };
                Event::AgentChunk {
                    key,
                    content: gen_content(&mut rng),
                }
            } else if roll < 80 {
                Event::Rewind {
                    target: rng.below(6) as u64,
                }
            } else if roll < 86 {
                Event::UserChunk {
                    key: None,
                    content: Content::Bash,
                }
            } else if roll < 92 {
                match rng.below(3) {
                    0 => Event::Unknown,
                    1 => Event::NoUpdate,
                    _ => Event::Blank(if rng.chance(1, 2) {
                        String::new()
                    } else {
                        "   ".to_string()
                    }),
                }
            } else {
                Event::Malformed(rng.pick(&MALFORMED_POOL).to_string())
            }
        };
        let line = render_event(&ev);
        sim.run(&ev, &line);
        rendered.push(line);
    }

    // 属性前提是"存在有效记录"；极端种子下若一条未生成则强制补一条。
    if sim.messages.is_empty() {
        let ev = Event::UserChunk {
            key: Some(99),
            content: Content::Text("forced valid record".to_string()),
        };
        let line = render_event(&ev);
        sim.run(&ev, &line);
        rendered.push(line);
    }

    // 渲染字节：逐行随机 LF / CRLF；末行 1/4 概率不带行尾符。
    let mut bytes = Vec::new();
    let total = rendered.len();
    for (idx, line) in rendered.iter().enumerate() {
        bytes.extend_from_slice(line.as_bytes());
        let is_last = idx + 1 == total;
        if is_last && rng.chance(1, 4) {
            break;
        }
        bytes.extend_from_slice(if rng.chance(1, 2) { b"\r\n" } else { b"\n" });
    }

    Case {
        bytes,
        expected: sim
            .messages
            .iter()
            .map(|m| ExpectedMessage {
                role: if m.is_user { "user" } else { "assistant" }.to_string(),
                text: m.text.clone(),
                span_line: m.span_line.clone(),
            })
            .collect(),
        session_id: sim.session_ids.first().cloned(),
        multi_session: sim.session_ids.len() > 1,
        malformed: sim.skipped,
        merged: sim.merged,
        rewind_hit: sim.rewind_hit,
        bash_seen: sim.bash_seen,
    }
}

fn parse_case(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = GrokBuildAdapter::new()
        .parse(bytes, &mut sink)
        .unwrap_or_else(|e| panic!("seed={seed}: 含有效记录的合成流 parse 整体失败：{e}"));
    (report, sink.messages)
}

/// 逐固定种子运行 body；index 0 的迭代携带 ~256 KiB 大字段。
fn for_each_seed(mut body: impl FnMut(u64, &Case)) {
    for (idx, &seed) in fixed_seeds().iter().enumerate() {
        let case = build_case(seed, idx == 0);
        body(seed, &case);
    }
}

/// 性质 1：每条消息的 span 切回快照字节 == 其首个 chunk 的源记录行（去行尾），
/// 对任意 Unicode 内容、混合行尾与大字段均成立。
#[test]
fn prop_span_roundtrips_to_first_chunk_line() {
    for_each_seed(|seed, case| {
        let (_, captured) = parse_case(seed, &case.bytes);
        assert_eq!(
            captured.len(),
            case.expected.len(),
            "seed={seed}: 消息数必须等于 ground truth"
        );
        for (got, want) in captured.iter().zip(&case.expected) {
            let (start, end) = got
                .span
                .unwrap_or_else(|| panic!("seed={seed} seq={}: 消息必须携带 span", got.seq));
            assert_eq!(
                &case.bytes[start as usize..end as usize],
                want.span_line.as_bytes(),
                "seed={seed} seq={}: span 切片必须逐字节等于首个 chunk 源行（去行尾）",
                got.seq
            );
        }
    });
}

/// 性质 2：seq 从 0 连续，且 committed == emit 数 == ground truth 消息数。
#[test]
fn prop_seq_contiguous_and_counts_committed() {
    for_each_seed(|seed, case| {
        let (report, captured) = parse_case(seed, &case.bytes);
        for (i, got) in captured.iter().enumerate() {
            assert_eq!(got.seq, i as u32, "seed={seed}: seq 必须从 0 连续递增");
        }
        assert_eq!(
            report.committed,
            captured.len(),
            "seed={seed}: committed 必须等于实际 emit 的消息数"
        );
        assert_eq!(
            report.committed,
            case.expected.len(),
            "seed={seed}: committed 必须等于 ground truth 有效消息数"
        );
    });
}

/// 性质 3：同一字节输入解析两次，事件流与报告完全一致（确定性）。
#[test]
fn prop_parse_is_deterministic() {
    for_each_seed(|seed, case| {
        let (report_a, captured_a) = parse_case(seed, &case.bytes);
        let (report_b, captured_b) = parse_case(seed, &case.bytes);
        assert_eq!(report_a, report_b, "seed={seed}: 两次解析的报告必须一致");
        assert_eq!(
            captured_a, captured_b,
            "seed={seed}: 两次解析收集的事件必须一致"
        );
    });
}

/// 性质 4：role / 累积文本相对 ground truth 原样透传；grok 无原生消息 id、
/// 无 threading、无消息级时间戳、无 sidechain——这些字段恒为契约默认值。
#[test]
fn prop_metadata_survives_verbatim() {
    for_each_seed(|seed, case| {
        let (_, captured) = parse_case(seed, &case.bytes);
        assert_eq!(
            captured.len(),
            case.expected.len(),
            "seed={seed}: 消息数必须等于 ground truth"
        );
        for (got, want) in captured.iter().zip(&case.expected) {
            let seq = got.seq;
            assert_eq!(
                got.role, want.role,
                "seed={seed} seq={seq}: role 必须原样透传"
            );
            assert_eq!(
                got.text, want.text,
                "seed={seed} seq={seq}: 文本必须等于 chunk 累积结果"
            );
            assert_eq!(
                got.native_id, "",
                "seed={seed} seq={seq}: grok 无原生消息 id，native_id 恒空"
            );
            assert_eq!(
                got.parent_native_id, None,
                "seed={seed} seq={seq}: grok 无 threading 边"
            );
            assert_eq!(
                got.timestamp, None,
                "seed={seed} seq={seq}: grok 不提取消息级时间戳"
            );
            assert!(
                !got.is_sidechain,
                "seed={seed} seq={seq}: grok 无 sidechain"
            );
        }
    });
}

/// 性质 5：session_native_id == 首个 agent promptId；多 id 时 multi_session 置位、
/// provider_session_id fail-closed 为 Ambiguous；无 id 时保持 Missing。
#[test]
fn prop_session_identity_matches_ground_truth() {
    for_each_seed(|seed, case| {
        let (report, _) = parse_case(seed, &case.bytes);
        assert_eq!(
            report.session_native_id, case.session_id,
            "seed={seed}: session_native_id 必须等于首个 agent promptId"
        );
        assert_eq!(
            report.session_observation.multi_session, case.multi_session,
            "seed={seed}: multi_session 必须与 ground truth 一致"
        );
        match (case.session_id.as_deref(), case.multi_session) {
            (Some(id), false) => assert_eq!(
                report.session_observation.provider_session_id,
                MetadataResolution::Resolved(id.to_string()),
                "seed={seed}: 单会话 provider_session_id 必须 Resolved"
            ),
            (Some(_), true) => assert_eq!(
                report.session_observation.provider_session_id,
                MetadataResolution::Ambiguous,
                "seed={seed}: 多会话 provider_session_id 必须 fail-closed 为 Ambiguous"
            ),
            (None, _) => assert_eq!(
                report.session_observation.provider_session_id,
                MetadataResolution::Missing,
                "seed={seed}: 无会话 id 时 provider_session_id 必须 Missing"
            ),
        }
    });
}

/// 性质 6：坏行只递增 skipped/diagnostics，绝不吞消息、绝不中止解析。
/// grok 的 diagnostics 恰好 = 坏行数 +（多会话 ? 1 : 0）。
#[test]
fn prop_malformed_lines_only_skip_never_abort() {
    for_each_seed(|seed, case| {
        let (report, captured) = parse_case(seed, &case.bytes);
        assert_eq!(
            report.skipped, case.malformed,
            "seed={seed}: skipped 必须恰等于注入的坏行数"
        );
        assert_eq!(
            report.diagnostics.len(),
            case.malformed + usize::from(case.multi_session),
            "seed={seed}: 诊断数必须 = 坏行数 + 多会话诊断"
        );
        assert_eq!(
            captured.len(),
            case.expected.len(),
            "seed={seed}: 坏行不得吞掉或伪造任何消息"
        );
    });
}

/// 语料覆盖度：64 个固定种子必须实际exercise过合并、rewind 截断、bash 元块、
/// 坏行与"有/无会话 id"两种分支——防止生成器退化成空转语料。
#[test]
fn prop_corpus_coverage_is_not_degenerate() {
    let mut saw_merged = false;
    let mut saw_rewind = false;
    let mut saw_bash = false;
    let mut saw_malformed = false;
    let mut saw_session = false;
    let mut saw_no_session = false;
    for (i, seed) in fixed_seeds().iter().copied().enumerate() {
        let case = build_case(seed, i == 0);
        saw_merged |= case.merged;
        saw_rewind |= case.rewind_hit;
        saw_bash |= case.bash_seen;
        saw_malformed |= case.malformed > 0;
        saw_session |= case.session_id.is_some();
        saw_no_session |= case.session_id.is_none();
        assert!(
            !case.expected.is_empty(),
            "seed={seed}: 每个用例必须至少含一条有效消息"
        );
    }
    assert!(
        saw_merged && saw_rewind && saw_bash && saw_malformed && saw_session && saw_no_session,
        "生成器语料退化：merged={saw_merged} rewind={saw_rewind} bash={saw_bash} \
         malformed={saw_malformed} session={saw_session} no_session={saw_no_session}"
    );
}

/// 只读契约：合成语料的 probe 与 parse 前后字节长度与 BLAKE3 指纹不变
/// （RFC-0002 §7 的可执行守护）。
#[test]
fn prop_probe_and_parse_are_read_only() {
    for_each_seed(|seed, case| {
        let report = assert_read_only(&case.bytes, |src| {
            let mut sink = CollectingSink::default();
            GrokBuildAdapter::new().parse(src, &mut sink)
        })
        .unwrap_or_else(|e| panic!("seed={seed}: 合成流 parse 失败：{e}"));
        assert!(report.committed > 0, "seed={seed}: 合成流必须产出消息");
        let _ = assert_read_only(&case.bytes, |src| GrokBuildAdapter::new().probe(src));
    });
}

/// probe 对任意字节永不 panic：纯随机 / 随机 ASCII 文本行 / 随机 JSON 状行 /
/// golden 随机截断。Ok 时 confidence 绝不 Ambiguous（歧义即拒绝，RFC-0002 §3）
/// 且 variant 恒为自身；Err 是可接受的拒绝路径。
#[test]
fn prop_probe_never_panics_on_arbitrary_bytes() {
    let adapter = GrokBuildAdapter::new();
    let fixture = std::fs::read(FIXTURE_PATH).expect("read golden fixture");

    for seed in fixed_seeds() {
        let mut rng = XorShift64Star::new(seed.wrapping_mul(0x1234_5678_9ABC_DEF1).max(1));
        for k in 0..8 {
            let bytes = match k % 4 {
                0 => {
                    let n = rng.below(2048);
                    (0..n).map(|_| rng.next_u64() as u8).collect::<Vec<_>>()
                }
                1 => {
                    let n = 1 + rng.below(16);
                    let mut s = String::new();
                    for _ in 0..n {
                        let len = rng.below(64);
                        for _ in 0..len {
                            s.push((0x20 + rng.below(0x5F)) as u8 as char);
                        }
                        s.push('\n');
                    }
                    s.into_bytes()
                }
                2 => {
                    const KINDS: [&str; 4] = [
                        "user_message_chunk",
                        "agent_message_chunk",
                        "rewind_marker",
                        "garbage_kind",
                    ];
                    let n = 1 + rng.below(8);
                    let mut s = String::new();
                    for _ in 0..n {
                        s.push_str(&format!(
                            r#"{{"params":{{"update":{{"sessionUpdate":"{}"}}}}}}"#,
                            rng.pick(&KINDS)
                        ));
                        s.push('\n');
                    }
                    s.into_bytes()
                }
                _ => {
                    let mut b = fixture.clone();
                    b.truncate(rng.below(b.len()));
                    b
                }
            };
            let probed = catch_unwind(AssertUnwindSafe(|| adapter.probe(&bytes)));
            match probed {
                Ok(Ok(r)) => {
                    assert_ne!(
                        r.confidence,
                        Confidence::Ambiguous,
                        "seed={seed} k={k}: probe Ok 时 confidence 不得为 Ambiguous"
                    );
                    assert_eq!(
                        r.variant_id, VARIANT_ID,
                        "seed={seed} k={k}: probe 必须报告自身 variant"
                    );
                }
                Ok(Err(_)) => {}
                Err(payload) => panic!(
                    "seed={seed} k={k}: probe 在 {} 字节任意输入上 panic: {payload:?}",
                    bytes.len()
                ),
            }
        }
    }
}

/// 合成语料上的 probe：不 panic、两次调用结果一致，且 Ok 时报告自身 variant、
/// confidence 非 Ambiguous（chunk 证据充分时通常为 Confirmed/High）。
#[test]
fn prop_probe_on_generated_streams_reports_own_variant() {
    for_each_seed(|seed, case| {
        let adapter = GrokBuildAdapter::new();
        let a = adapter.probe(&case.bytes);
        let b = adapter.probe(&case.bytes);
        assert_eq!(a, b, "seed={seed}: probe 两次调用必须确定一致");
        if let Ok(r) = a {
            assert_ne!(
                r.confidence,
                Confidence::Ambiguous,
                "seed={seed}: probe Ok 时 confidence 不得为 Ambiguous"
            );
            assert_eq!(
                r.variant_id, VARIANT_ID,
                "seed={seed}: probe 必须报告自身 variant"
            );
        }
    });
}

/// golden fixture 的 seeded 确定性变异：截断 / 插入 / 删除 / 翻转 / 拆行 / 乱序行。
fn mutate_bytes(rng: &mut XorShift64Star, base: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    match rng.below(6) {
        0 => {
            // 随机位置截断。
            let pos = rng.below(out.len());
            out.truncate(pos);
        }
        1 => {
            // 随机位置插入 1..=24 个随机字节。
            let pos = rng.below(out.len());
            let n = 1 + rng.below(24);
            let filler: Vec<u8> = (0..n).map(|_| rng.next_u64() as u8).collect();
            out.splice(pos..pos, filler);
        }
        2 => {
            // 随机位置删除 1..=24 个字节。
            let pos = rng.below(out.len());
            let n = (1 + rng.below(24)).min(out.len() - pos);
            out.drain(pos..pos + n);
        }
        3 => {
            // 翻转一个字节。
            let pos = rng.below(out.len());
            out[pos] = rng.next_u64() as u8;
        }
        4 => {
            // 拆行：行内随机位置插入换行，把一条 JSON 记录拆成两行。
            let pos = rng.below(out.len());
            out.insert(pos, b'\n');
        }
        _ => {
            // 乱序行：随机交换两行。
            let mut lines: Vec<Vec<u8>> = out.split(|b| *b == b'\n').map(|s| s.to_vec()).collect();
            if lines.len() >= 2 {
                let a = rng.below(lines.len());
                let b = rng.below(lines.len());
                lines.swap(a, b);
            }
            out.clear();
            for (i, line) in lines.iter().enumerate() {
                if i > 0 {
                    out.push(b'\n');
                }
                out.extend_from_slice(line);
            }
        }
    }
    out
}

/// 变异语料上的 parse：永不 panic；Err 即 recoverable 拒绝（上层回滚 staging）；
/// Ok 则绝不 partial commit——committed == emit 数、seq 连续、span 界内且回切
/// 到完整源行、正文非空、chunk 种类与角色一致。同时 probe 变异字节不 panic，
/// 且源字节在 parse 前后不变（RFC-0002 §7）。
#[test]
fn prop_golden_mutations_never_panic_and_output_stays_legal() {
    let fixture = std::fs::read(FIXTURE_PATH).expect("read golden fixture");
    let adapter = GrokBuildAdapter::new();

    for seed in fixed_seeds() {
        let mut rng = XorShift64Star::new(seed.wrapping_add(0xA5A5_5A5A_DEAD_BEEF).max(1));
        for op in 0..12 {
            let mutated = mutate_bytes(&mut rng, &fixture);

            let (parsed, sink) = assert_read_only(&mutated, |src| {
                let mut sink = CollectingSink::default();
                let parsed = catch_unwind(AssertUnwindSafe(|| adapter.parse(src, &mut sink)));
                (parsed, sink)
            });
            let report = match parsed {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => continue, // recoverable 错误路径：允许并继续
                Err(payload) => {
                    panic!("seed={seed} op={op}: parse 在变异输入上 panic: {payload:?}")
                }
            };

            assert_eq!(
                report.committed,
                sink.messages.len(),
                "seed={seed} op={op}: committed 必须等于实际 emit 数（绝不 partial commit）"
            );
            for (i, m) in sink.messages.iter().enumerate() {
                assert_eq!(m.seq, i as u32, "seed={seed} op={op}: seq 必须从 0 连续");
                assert!(
                    matches!(m.role.as_str(), "user" | "assistant"),
                    "seed={seed} op={op}: 角色必须是 user/assistant，实际 {}",
                    m.role
                );
                assert!(
                    !m.text.is_empty(),
                    "seed={seed} op={op}: seq={} 正文为空，committed 计入它等于宣称索引了检索不到的内容",
                    m.seq
                );
                let (start, end) = m
                    .span
                    .unwrap_or_else(|| panic!("seed={seed} op={op}: seq={} 必须携带 span", m.seq));
                assert!(
                    start <= end && end as usize <= mutated.len(),
                    "seed={seed} op={op}: span ({start},{end}) 越界（len={}）",
                    mutated.len()
                );
                // span 回切：必须指向一条完整源行（去行尾），且是 chunk 记录。
                let rest = &mutated[start as usize..];
                let line_len = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
                let line = &rest[..line_len];
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                assert_eq!(
                    end - start,
                    line.len() as u64,
                    "seed={seed} op={op}: seq={} span 长度必须等于其源行（去行尾）字节长",
                    m.seq
                );
                assert_eq!(
                    &mutated[start as usize..end as usize],
                    line,
                    "seed={seed} op={op}: seq={} span 切片必须与源行逐字节一致",
                    m.seq
                );
                let rec: Value = serde_json::from_slice(line).unwrap_or_else(|e| {
                    panic!(
                        "seed={seed} op={op}: seq={} span 指向的行必须是完整 JSON 记录: {e}",
                        m.seq
                    )
                });
                let kind = rec["params"]["update"]["sessionUpdate"]
                    .as_str()
                    .unwrap_or("");
                let expected_kind = if m.role == "user" {
                    "user_message_chunk"
                } else {
                    "agent_message_chunk"
                };
                assert_eq!(
                    kind, expected_kind,
                    "seed={seed} op={op}: seq={} span 指向的 chunk 种类必须与角色一致",
                    m.seq
                );
            }

            // probe 同样必须对变异字节不 panic。
            let probed = catch_unwind(AssertUnwindSafe(|| adapter.probe(&mutated)));
            match probed {
                Ok(Ok(r)) => {
                    assert_ne!(
                        r.confidence,
                        Confidence::Ambiguous,
                        "seed={seed} op={op}: probe Ok 时 confidence 不得为 Ambiguous"
                    );
                    assert_eq!(
                        r.variant_id, VARIANT_ID,
                        "seed={seed} op={op}: probe 必须报告自身 variant"
                    );
                }
                Ok(Err(_)) => {}
                Err(payload) => {
                    panic!("seed={seed} op={op}: probe 在变异输入上 panic: {payload:?}")
                }
            }
        }
    }
}
