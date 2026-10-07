//! Pi adapter（`pi/session-jsonl-v1`）的确定性 property 套件。
//!
//! 用固定种子生成随机 type-discriminated session JSONL（session 头 / message
//! 记录 / 无 body 的 message / session_info 等非会话类型 / 坏行 / 混合行尾），
//! 逐条验证结构不变量：
//!
//! 1. span 回切：每条消息的 span 切回快照字节等于其源 message 行（去行尾）；
//! 2. seq 从 0 连续，committed == emit 数 == ground truth 消息数；
//! 3. 确定性：同一字节两次解析，事件流与报告完全一致；
//! 4. 元数据透传：role/text/timestamp 原样（msg 级时间戳优先、record 级回退）、
//!    native_id 恒空、无 parent/sidechain；
//! 5. 会话身份：session_native_id == 首个 session 头 id，cwd pair 同源保留，
//!    多 id 时 fail-closed 为 Ambiguous；
//! 6. 坏行与无 body 的 message 只递增 skipped/diagnostics，绝不吞消息、绝不中止；
//! 7. probe 对任意字节永不 panic；Ok 时 confidence 非 Ambiguous 且 variant 恒为自身；
//! 8. v2/v3 会话树血缘（头部 `version` + 逐条 `id`/`parentId`，含同 parentId 的
//!    分支）必须被如实上报为一条诊断而非静默按线性解析，且 Pi 的 entry id 不得
//!    被提升为 native 消息身份。
//!
//! 另含 golden fixture 的 seeded 确定性变异（截断 / 插入 / 删除 / 翻转 / 拆行 /
//! 乱序行）语料：parse 永不 panic——Ok 则消息字段合法（span 界内且回切源行、
//! committed==emit、正文非空、span 行与角色/正文/时间戳自洽），Err 则 recoverable
//! 由上层回滚；变异源字节前后不变（RFC-0002 §7，经 testkit `assert_read_only`）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表；断言信息一律携带
//! seed，失败可用该 seed 单独重放；不落盘、不联网。

use std::panic::{AssertUnwindSafe, catch_unwind};

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_pi::{PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX, PiAdapter};
use agent_session_grep_testkit::assert_read_only;
use serde_json::{Value, json};

const VARIANT_ID: &str = "pi/session-jsonl-v1";
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.jsonl");
const V3_FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/v3-branched.jsonl"
);

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
    "session 记录自检",
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
    r#"{"type":"message","message":{"role":"user","content":"torn"#,
    "{ not json at all",
    "]]]",
    "\"unterminated string",
    "42 trailing garbage }",
];

/// 会话头 id 小池：多会话分支靠池内复用触发。
const SESSION_IDS: [&str; 3] = ["sess-prop-a", "sess-prop-b", "sess-prop-c"];

/// 非会话 type 池：全部静默略过。
const NON_CONVERSATIONAL: [&str; 5] = [
    "session_info",
    "compaction",
    "custom_message",
    "branch_summary",
    "x-future-kind",
];

/// 一条预期产出的消息：角色、正文、时间戳与源记录行（span 回切对照物）。
struct ExpectedMessage {
    role: String,
    text: String,
    timestamp: Option<String>,
    line: String,
}

/// 一个生成的 Pi session 流用例：快照字节 + 全部预期值 + 语料覆盖度标志。
struct Case {
    bytes: Vec<u8>,
    expected: Vec<ExpectedMessage>,
    /// 坏行 + 无 body 的 message 行——skipped 口径。
    skipped: usize,
    session_id: Option<String>,
    multi_session: bool,
    cwd: Option<String>,
    saw_bodyless: bool,
    saw_non_conversational: bool,
    saw_empty_content: bool,
    saw_msg_ts_number: bool,
    /// 本用例是否注入了 v3 形态（头部 `version` + 逐条 `id`/`parentId`）。
    lineage_shaped: bool,
    /// 携带非空 `parentId` 的记录数（含非对话记录）。
    lineage_records: usize,
    /// 是否应恰好产生一条会话树血缘诊断（version>=2 或存在非空 parentId）。
    lineage_expected: bool,
    /// 是否生成了同一 `parentId` 的两条以上子记录（真实分支）。
    saw_branch: bool,
}

/// message.content 形态；`text()` 与生产 `pi_content_text` 的抽取结果一致。
enum PiContent {
    Str(String),
    /// `{type:"text", text:...}` 块数组（可夹带无 text 的块），text 块间 `\n` 拼接。
    Blocks(Vec<Value>),
    /// 空 content（`""` / `[]` / `{}` / `null`）——text 为空 → 静默略过。
    Empty(Value),
    /// 非字符串/数组（数字等）——text 为空 → 静默略过。
    NonString(Value),
}

impl PiContent {
    fn text(&self) -> String {
        match self {
            PiContent::Str(s) => s.clone(),
            PiContent::Blocks(blocks) => {
                let mut buf = String::new();
                for block in blocks {
                    if block.get("type").and_then(Value::as_str) == Some("text")
                        && let Some(t) = block.get("text").and_then(Value::as_str)
                    {
                        if !buf.is_empty() {
                            buf.push('\n');
                        }
                        buf.push_str(t);
                    }
                }
                buf
            }
            PiContent::Empty(_) | PiContent::NonString(_) => String::new(),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            PiContent::Str(s) => json!(s),
            PiContent::Blocks(blocks) => Value::Array(blocks.clone()),
            PiContent::Empty(v) | PiContent::NonString(v) => v.clone(),
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

fn gen_content(rng: &mut XorShift64Star) -> PiContent {
    match rng.below(20) {
        0..=9 => PiContent::Str(gen_text(rng)),
        10..=14 => {
            let n = 1 + rng.below(3);
            let blocks: Vec<Value> = (0..n)
                .map(|_| {
                    if rng.chance(7, 10) {
                        json!({"type": "text", "text": gen_text(rng)})
                    } else {
                        // 无 text 的块（如图片）——抽取时忽略。
                        json!({"type": "image", "url": "synthetic://fixture.png"})
                    }
                })
                .collect();
            PiContent::Blocks(blocks)
        }
        15..=17 => PiContent::Empty(match rng.below(4) {
            0 => json!(""),
            1 => json!([]),
            2 => json!({}),
            _ => Value::Null,
        }),
        _ => PiContent::NonString(json!(42)),
    }
}

fn build_case(seed: u64, with_big_field: bool) -> Case {
    let mut rng = XorShift64Star::new(seed);
    let mut expected: Vec<ExpectedMessage> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();
    let mut skipped = 0usize;
    let mut session_id: Option<String> = None;
    let mut session_ids: Vec<String> = Vec::new();
    let mut cwd: Option<String> = None;
    let mut saw_bodyless = false;
    let mut saw_non_conversational = false;
    let mut saw_empty_content = false;
    let mut saw_msg_ts_number = false;

    // v3 形态：一半种子把语料生成成 parent-linked 会话树（头部 version=3 +
    // 逐条 8 位十六进制 entry id + parentId），另一半保持 v1 线性——两侧都必须
    // 被覆盖，否则诊断的正/负向都无从检验。
    let lineage_shaped = rng.chance(1, 2);
    let mut entry_counter: u32 = 0;
    let mut emitted_ids: Vec<String> = Vec::new();
    let mut lineage_records = 0usize;
    let mut versioned_headers = 0usize;
    let mut saw_branch = false;
    let mut parented: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    // 会话头配额 0..=3：25% 的种子没有任何 session 头 → 无会话 id 分支。
    let n_header_quota = rng.below(4);
    let mut headers_emitted = 0usize;

    let line_count = 8 + rng.below(28);
    for i in 0..line_count {
        let roll = rng.next_u64() % 100;
        let (record, maybe_msg) = if with_big_field && i == 0 {
            let lineage = lineage_shaped.then(|| {
                assign_lineage(
                    &mut rng,
                    &mut entry_counter,
                    &mut emitted_ids,
                    &mut lineage_records,
                    &mut parented,
                    &mut saw_branch,
                )
            });
            let record = render_message(
                "user",
                &PiContent::Str(big_text()),
                None,
                Some("2026-01-01T00:00:00Z"),
                lineage
                    .as_ref()
                    .map(|(id, parent)| (id.as_str(), parent.as_deref())),
            );
            (
                record,
                Some((
                    "user".to_string(),
                    big_text(),
                    Some("2026-01-01T00:00:00Z".to_string()),
                )),
            )
        } else if roll < 25 && headers_emitted < n_header_quota {
            headers_emitted += 1;
            let id = if rng.chance(3, 4) {
                Some(rng.pick(&SESSION_IDS))
            } else {
                Some("   ")
            };
            let id_value = id
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string());
            let cwd_value = if rng.chance(1, 2) {
                Some("/synthetic/workspace")
            } else {
                None
            };
            if let Some(id) = &id_value {
                if session_id.is_none() {
                    session_id = Some(id.clone());
                }
                if !session_ids.iter().any(|s| s == id) {
                    session_ids.push(id.clone());
                }
                if cwd.is_none()
                    && let Some(c) = cwd_value
                {
                    cwd = Some(c.to_string());
                }
            }
            let mut record = json!({"type": "session"});
            if let Some(id) = id {
                record["id"] = json!(id);
            }
            if let Some(c) = cwd_value {
                record["cwd"] = json!(c);
            }
            if rng.chance(1, 2) {
                record["timestamp"] = json!("2026-01-01T00:00:00Z");
            }
            if lineage_shaped {
                // 会话头的 `id` 是会话身份，不是 entry id；v3 的判别位是 `version`。
                record["version"] = json!(3);
                versioned_headers += 1;
            }
            (record.to_string(), None)
        } else if roll < 65 {
            // message 记录：role user/assistant 产出消息，其余静默略过。
            let role = match rng.below(20) {
                0..=7 => "user",
                8..=15 => "assistant",
                16..=18 => "system",
                _ => "tool",
            };
            let content = gen_content(&mut rng);
            let text = content.text();
            if matches!(&content, PiContent::Empty(_) | PiContent::NonString(_)) {
                // 空/非字符串 content 走"静默略过"路径（对 user/assistant 亦然）。
                saw_empty_content = true;
            }
            // msg 级时间戳：字符串（优先）/ 数字（回退 record 级）/ 缺席。
            let (msg_ts, rec_ts) = match rng.below(10) {
                0..=5 => (None, rng.chance(1, 2).then_some("2026-01-01T00:01:00Z")),
                6..=8 => (Some(json!("2026-01-01T00:01:00Z")), None),
                _ => {
                    saw_msg_ts_number = true;
                    (Some(json!(123456)), Some("2026-01-01T00:01:00Z"))
                }
            };
            let record = render_message(
                role,
                &content,
                msg_ts.as_ref(),
                rec_ts,
                lineage_shaped
                    .then(|| {
                        assign_lineage(
                            &mut rng,
                            &mut entry_counter,
                            &mut emitted_ids,
                            &mut lineage_records,
                            &mut parented,
                            &mut saw_branch,
                        )
                    })
                    .as_ref()
                    .map(|(id, parent)| (id.as_str(), parent.as_deref())),
            );
            let msg = if matches!(role, "user" | "assistant") && !text.trim().is_empty() {
                let timestamp = msg_ts
                    .as_ref()
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| rec_ts.map(str::to_string));
                Some((role.to_string(), text, timestamp))
            } else {
                None
            };
            (record, msg)
        } else if roll < 72 {
            // message 记录但缺 message body：record_recoverable，计 skipped。
            saw_bodyless = true;
            skipped += 1;
            let mut record = json!({
                "type": "message",
                "timestamp": "2026-01-01T00:02:00Z",
            });
            if lineage_shaped {
                let (id, parent) = assign_lineage(
                    &mut rng,
                    &mut entry_counter,
                    &mut emitted_ids,
                    &mut lineage_records,
                    &mut parented,
                    &mut saw_branch,
                );
                record["id"] = json!(id);
                record["parentId"] = parent.map_or(Value::Null, |parent| json!(parent));
            }
            (record.to_string(), None)
        } else if roll < 80 {
            // 非会话 type：静默略过，不计 skipped——但它同样是会话树节点，
            // 其 parentId 必须计入血缘事实，否则会低报"这是一棵树"。
            saw_non_conversational = true;
            let kind = rng.pick(&NON_CONVERSATIONAL).to_string();
            let mut record = json!({
                "type": kind,
                "name": "synthetic",
            });
            if lineage_shaped {
                let (id, parent) = assign_lineage(
                    &mut rng,
                    &mut entry_counter,
                    &mut emitted_ids,
                    &mut lineage_records,
                    &mut parented,
                    &mut saw_branch,
                );
                record["id"] = json!(id);
                record["parentId"] = parent.map_or(Value::Null, |parent| json!(parent));
            }
            (record.to_string(), None)
        } else if roll < 92 {
            skipped += 1;
            (rng.pick(&MALFORMED_POOL).to_string(), None)
        } else {
            (
                if rng.chance(1, 2) {
                    String::new()
                } else {
                    "   ".to_string()
                },
                None,
            )
        };

        if let Some((role, text, timestamp)) = maybe_msg {
            expected.push(ExpectedMessage {
                role,
                text,
                timestamp,
                line: record.clone(),
            });
        }
        rendered.push(record);
    }

    // 属性前提是"存在有效记录"；极端种子下若一条未生成则强制补一条。
    if expected.is_empty() {
        let lineage = lineage_shaped.then(|| {
            assign_lineage(
                &mut rng,
                &mut entry_counter,
                &mut emitted_ids,
                &mut lineage_records,
                &mut parented,
                &mut saw_branch,
            )
        });
        let record = render_message(
            "user",
            &PiContent::Str("forced valid record".to_string()),
            None,
            None,
            lineage
                .as_ref()
                .map(|(id, parent)| (id.as_str(), parent.as_deref())),
        );
        expected.push(ExpectedMessage {
            role: "user".to_string(),
            text: "forced valid record".to_string(),
            timestamp: None,
            line: record.clone(),
        });
        rendered.push(record);
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
        expected,
        skipped,
        session_id,
        multi_session: session_ids.len() > 1,
        cwd,
        saw_bodyless,
        saw_non_conversational,
        saw_empty_content,
        saw_msg_ts_number,
        lineage_shaped,
        lineage_records,
        lineage_expected: lineage_records > 0 || versioned_headers > 0,
        saw_branch,
    }
}

fn render_message(
    role: &str,
    content: &PiContent,
    msg_ts: Option<&Value>,
    rec_ts: Option<&str>,
    lineage: Option<(&str, Option<&str>)>,
) -> String {
    let mut message = json!({"role": role, "content": content.to_json()});
    if let Some(ts) = msg_ts {
        message["timestamp"] = ts.clone();
    }
    let mut record = json!({"type": "message", "message": message});
    if let Some((id, parent)) = lineage {
        record["id"] = json!(id);
        record["parentId"] = match parent {
            Some(parent) => json!(parent),
            None => Value::Null,
        };
    }
    if let Some(ts) = rec_ts {
        record["timestamp"] = json!(ts);
    }
    record.to_string()
}

/// 给一条 v3 记录分配 entry id 与 `parentId`。
///
/// id 形如 `aa0000xx`——刻意复刻真实 Pi 的 8 位十六进制 entry id（本机证据：
/// agent-sessions 的 pi stage0 fixture），因为"仅文件内唯一的短 id"正是本
/// adapter 不把它提升为 native 消息身份的原因。返回的 parent 为 `None` 表示
/// 显式 `null` 根记录；1/3 概率挂到较早的记录上，从而生成同 parentId 的真实分支。
fn assign_lineage(
    rng: &mut XorShift64Star,
    counter: &mut u32,
    emitted: &mut Vec<String>,
    lineage_records: &mut usize,
    parented: &mut std::collections::BTreeMap<String, usize>,
    saw_branch: &mut bool,
) -> (String, Option<String>) {
    let id = format!("{:08x}", 0xaa00_0000u32 + *counter);
    *counter += 1;
    let parent = if emitted.is_empty() || rng.chance(1, 8) {
        None
    } else if rng.chance(1, 3) {
        Some(emitted[rng.below(emitted.len())].clone())
    } else {
        Some(emitted[emitted.len() - 1].clone())
    };
    if let Some(parent) = &parent {
        *lineage_records += 1;
        let children = parented.entry(parent.clone()).or_insert(0);
        *children += 1;
        if *children >= 2 {
            *saw_branch = true;
        }
    }
    emitted.push(id.clone());
    (id, parent)
}

fn parse_case(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = PiAdapter::new()
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

/// 性质 1：每条消息的 span 切回快照字节 == 其源 message 行（去行尾），
/// 对任意 Unicode 内容、混合行尾与大字段均成立。
#[test]
fn prop_span_roundtrips_to_source_message_line() {
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
                want.line.as_bytes(),
                "seed={seed} seq={}: span 切片必须逐字节等于源 message 行（去行尾）",
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

/// 性质 4：role / text / timestamp 相对 ground truth 原样透传（msg 级时间戳
/// 优先、record 级回退）；native_id 恒空、无 parent、无 sidechain。
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
                "seed={seed} seq={seq}: 文本必须等于 content 抽取结果"
            );
            assert_eq!(
                got.timestamp, want.timestamp,
                "seed={seed} seq={seq}: timestamp 必须等于 msg 级（字符串）或 record 级回退"
            );
            assert_eq!(
                got.native_id, "",
                "seed={seed} seq={seq}: Pi 的 entry id 仅文件内唯一，不得提升为 native_id"
            );
            assert_eq!(
                got.parent_native_id, None,
                "seed={seed} seq={seq}: v2/v3 的 parentId 只上报为诊断，不发出 parent 边"
            );
            assert!(!got.is_sidechain, "seed={seed} seq={seq}: pi 无 sidechain");
        }
    });
}

/// 性质 5：会话身份——session_native_id == 首个 session 头 id；cwd 与首个 id
/// 同源保留；多 id 时 multi_session 置位且 provider_session_id fail-closed。
#[test]
fn prop_session_identity_matches_ground_truth() {
    for_each_seed(|seed, case| {
        let (report, _) = parse_case(seed, &case.bytes);
        assert_eq!(
            report.session_native_id, case.session_id,
            "seed={seed}: session_native_id 必须等于首个 session 头 id"
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
                "seed={seed}: 无会话头时 provider_session_id 必须 Missing"
            ),
        }
        match case.cwd.as_deref() {
            Some(cwd) => {
                assert_eq!(
                    report.session_observation.original_working_directory,
                    MetadataResolution::Resolved(cwd.to_string()),
                    "seed={seed}: cwd 必须与首个 session 头同源保留"
                );
                assert!(
                    report.session_observation.pair_observed,
                    "seed={seed}: cwd 观察到时必须 pair_observed"
                );
            }
            None => assert!(
                !report.session_observation.pair_observed,
                "seed={seed}: 无 cwd 时 pair_observed 必须为 false"
            ),
        }
    });
}

/// 性质 6：坏行与无 body 的 message 只递增 skipped/diagnostics（一一对应），
/// 绝不吞消息、绝不中止解析。diagnostics = skipped +（多会话 ? 1 : 0）
/// +（会话树血缘 ? 1 : 0）。
#[test]
fn prop_malformed_and_bodyless_lines_only_skip_never_abort() {
    for_each_seed(|seed, case| {
        let (report, captured) = parse_case(seed, &case.bytes);
        assert_eq!(
            report.skipped, case.skipped,
            "seed={seed}: skipped 必须恰等于注入的坏行 + 无 body message 数"
        );
        assert_eq!(
            report.diagnostics.len(),
            case.skipped + usize::from(case.multi_session) + usize::from(case.lineage_expected),
            "seed={seed}: 诊断数必须 = skipped + 多会话诊断 + 会话树血缘诊断"
        );
        assert_eq!(
            captured.len(),
            case.expected.len(),
            "seed={seed}: 坏行不得吞掉或伪造任何消息"
        );
    });
}

/// 性质 8：v2/v3 会话树血缘必须被如实上报，且只报一次。
///
/// 这条堵的是本切片修的那个缺陷：v3 文件会被 probe 命中并按线性解析，分支结构
/// 静默消失。正向——含 `version>=2` 或非空 `parentId` 的语料必须恰好一条诊断，
/// 且诊断里的血缘记录数与注入数逐字相等（含非对话记录）；负向——v1 线性语料
/// 一条也不能有，否则诊断退化成噪音。两侧都断言"消息数不变"：血缘上报绝不能
/// 以丢弃任何分支的正文为代价。
#[test]
fn prop_v3_lineage_is_reported_never_silently_dropped() {
    for_each_seed(|seed, case| {
        let (report, captured) = parse_case(seed, &case.bytes);
        let lineage: Vec<&String> = report
            .diagnostics
            .iter()
            .filter(|d| d.starts_with(PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX))
            .collect();
        assert_eq!(
            lineage.len(),
            usize::from(case.lineage_expected),
            "seed={seed}: 血缘诊断数必须与语料事实一致（lineage_shaped={}, \
             lineage_records={}）；实际诊断 {:?}",
            case.lineage_shaped,
            case.lineage_records,
            report.diagnostics
        );
        if let Some(diagnostic) = lineage.first() {
            assert!(
                diagnostic.contains(&format!("{} 条记录带 parentId", case.lineage_records)),
                "seed={seed}: 诊断必须报出注入的血缘记录数 {}，实际：{diagnostic}",
                case.lineage_records
            );
        }
        assert_eq!(
            captured.len(),
            case.expected.len(),
            "seed={seed}: 上报血缘不得以丢弃任何分支消息为代价"
        );
    });
}

/// 语料覆盖度：64 个固定种子必须实际exercise过无 body message、非会话类型、
/// 空 content、msg 级数字时间戳、有/无会话头——防止生成器退化成空转语料。
#[test]
fn prop_corpus_coverage_is_not_degenerate() {
    let mut saw_bodyless = false;
    let mut saw_other = false;
    let mut saw_empty = false;
    let mut saw_ts_number = false;
    let mut saw_session = false;
    let mut saw_no_session = false;
    let mut saw_lineage = false;
    let mut saw_no_lineage = false;
    let mut saw_branch = false;
    for (i, seed) in fixed_seeds().iter().copied().enumerate() {
        let case = build_case(seed, i == 0);
        saw_bodyless |= case.saw_bodyless;
        saw_other |= case.saw_non_conversational;
        saw_empty |= case.saw_empty_content;
        saw_ts_number |= case.saw_msg_ts_number;
        saw_session |= case.session_id.is_some();
        saw_no_session |= case.session_id.is_none();
        saw_lineage |= case.lineage_expected;
        saw_no_lineage |= !case.lineage_expected;
        saw_branch |= case.saw_branch;
        assert!(
            !case.expected.is_empty(),
            "seed={seed}: 每个用例必须至少含一条有效消息"
        );
    }
    assert!(
        saw_bodyless && saw_other && saw_empty && saw_ts_number && saw_session && saw_no_session,
        "生成器语料退化：bodyless={saw_bodyless} other={saw_other} empty={saw_empty} \
         ts_number={saw_ts_number} session={saw_session} no_session={saw_no_session}"
    );
    assert!(
        saw_lineage && saw_no_lineage && saw_branch,
        "生成器语料退化：v3 血缘的正/负向与真实分支必须都被覆盖——\
         lineage={saw_lineage} no_lineage={saw_no_lineage} branch={saw_branch}"
    );
}

/// 只读契约：合成语料的 probe 与 parse 前后字节长度与 BLAKE3 指纹不变
/// （RFC-0002 §7 的可执行守护）。
#[test]
fn prop_probe_and_parse_are_read_only() {
    for_each_seed(|seed, case| {
        let report = assert_read_only(&case.bytes, |src| {
            let mut sink = CollectingSink::default();
            PiAdapter::new().parse(src, &mut sink)
        })
        .unwrap_or_else(|e| panic!("seed={seed}: 合成流 parse 失败：{e}"));
        assert!(report.committed > 0, "seed={seed}: 合成流必须产出消息");
        let _ = assert_read_only(&case.bytes, |src| PiAdapter::new().probe(src));
    });
}

/// probe 对任意字节永不 panic：纯随机 / 随机 ASCII 文本行 / 随机 JSON 状行 /
/// golden 随机截断。Ok 时 confidence 非 Ambiguous 且 variant 恒为自身。
#[test]
fn prop_probe_never_panics_on_arbitrary_bytes() {
    let adapter = PiAdapter::new();
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
                    let n = 1 + rng.below(8);
                    let mut s = String::new();
                    for _ in 0..n {
                        s.push_str(&format!(
                            r#"{{"type":"{}","message":{{"role":"user"}}}}"#,
                            rng.pick(&["session", "message", "session_info", "garbage"])
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
/// confidence 非 Ambiguous。
#[test]
fn prop_probe_on_generated_streams_reports_own_variant() {
    for_each_seed(|seed, case| {
        let adapter = PiAdapter::new();
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
/// 到完整源行、正文非空，且 span 行必须与消息自洽（type=message、role 一致、
/// 正文等于该行 content 抽取、时间戳等于该行字段）。同时 probe 变异字节不
/// panic，且源字节在 parse 前后不变（RFC-0002 §7）。
#[test]
fn prop_golden_mutations_never_panic_and_output_stays_legal() {
    let fixture = std::fs::read(FIXTURE_PATH).expect("read golden fixture");
    let adapter = PiAdapter::new();

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
                    !m.text.trim().is_empty(),
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
                // span 回切：必须指向一条完整源行（去行尾），且是 message 记录。
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
                // span 行必须与消息自洽：消息正是从该行发出的。
                let rec: Value = serde_json::from_slice(line).unwrap_or_else(|e| {
                    panic!(
                        "seed={seed} op={op}: seq={} span 指向的行必须是完整 JSON 记录: {e}",
                        m.seq
                    )
                });
                assert_eq!(
                    rec.get("type").and_then(Value::as_str),
                    Some("message"),
                    "seed={seed} op={op}: seq={} span 行必须是 type=message 记录",
                    m.seq
                );
                assert_eq!(
                    rec.pointer("/message/role").and_then(Value::as_str),
                    Some(m.role.as_str()),
                    "seed={seed} op={op}: seq={} span 行的 role 必须与消息角色一致",
                    m.seq
                );
                let content = rec
                    .pointer("/message/content")
                    .cloned()
                    .unwrap_or(Value::Null);
                let expected_text = match &content {
                    Value::String(s) => s.clone(),
                    Value::Array(blocks) => {
                        let mut buf = String::new();
                        for block in blocks {
                            if block.get("type").and_then(Value::as_str) == Some("text")
                                && let Some(t) = block.get("text").and_then(Value::as_str)
                            {
                                if !buf.is_empty() {
                                    buf.push('\n');
                                }
                                buf.push_str(t);
                            }
                        }
                        buf
                    }
                    _ => String::new(),
                };
                assert_eq!(
                    m.text, expected_text,
                    "seed={seed} op={op}: seq={} 正文必须等于 span 行 content 的抽取结果",
                    m.seq
                );
                let expected_ts = rec
                    .pointer("/message/timestamp")
                    .and_then(Value::as_str)
                    .or_else(|| rec.get("timestamp").and_then(Value::as_str));
                assert_eq!(
                    m.timestamp.as_deref(),
                    expected_ts,
                    "seed={seed} op={op}: seq={} 时间戳必须等于 span 行的 msg 级或 record 级字段",
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

/// v3 golden 的 seeded 变异：截断/插入/删除/翻转/拆行/乱序行后，parse 永不 panic，
/// Ok 时不得偷偷把残缺的 `id`/`parentId` 变成消息身份或 parent 边——变异语料是最
/// 容易让"半解析出的 id"漏进身份路径的场景。源字节前后不变（RFC-0002 §7）。
#[test]
fn prop_v3_golden_mutations_never_promote_identity_or_panic() {
    let fixture = std::fs::read(V3_FIXTURE_PATH).expect("read v3 golden fixture");
    let adapter = PiAdapter::new();

    for seed in fixed_seeds() {
        let mut rng = XorShift64Star::new(seed.wrapping_add(0x5A5A_A5A5_C0FF_EE01).max(1));
        for op in 0..8 {
            let mutated = mutate_bytes(&mut rng, &fixture);
            let (parsed, sink) = assert_read_only(&mutated, |src| {
                let mut sink = CollectingSink::default();
                let parsed = catch_unwind(AssertUnwindSafe(|| adapter.parse(src, &mut sink)));
                (parsed, sink)
            });
            let report = match parsed {
                Ok(Ok(report)) => report,
                Ok(Err(_)) => continue,
                Err(payload) => {
                    panic!("seed={seed} op={op}: v3 变异输入上 parse panic: {payload:?}")
                }
            };
            assert_eq!(
                report.committed,
                sink.messages.len(),
                "seed={seed} op={op}: committed 必须等于实际 emit 数"
            );
            for m in &sink.messages {
                assert!(
                    m.native_id.is_empty(),
                    "seed={seed} op={op}: seq={} 变异语料也不得提升 entry id 为 native 身份",
                    m.seq
                );
                assert_eq!(
                    m.parent_native_id, None,
                    "seed={seed} op={op}: seq={} 不得发出 parent 边",
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
            }
            let lineage = report
                .diagnostics
                .iter()
                .filter(|d| d.starts_with(PI_BRANCH_LINEAGE_DIAGNOSTIC_PREFIX))
                .count();
            assert!(
                lineage <= 1,
                "seed={seed} op={op}: 血缘诊断最多一条，实际 {lineage}"
            );
        }
    }
}
