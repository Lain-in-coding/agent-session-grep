//! Antigravity adapter（`antigravity/transcript-jsonl-v1`）的确定性 property 套件。
//!
//! 用固定种子生成随机 step-record 流（USER_EXPLICIT / MODEL / SYSTEM /
//! CONVERSATION_HISTORY / 空正文 / 非字符串 content / 坏行 / 混合行尾），
//! 逐条验证结构不变量：
//!
//! 1. span 回切：每条消息的 span 切回快照字节等于其源 step 行（去行尾）；
//! 2. seq 从 0 连续，committed == emit 数 == ground truth 消息数；
//! 3. 确定性：同一字节两次解析，事件流与报告完全一致；
//! 4. 元数据透传：role/text/timestamp 原样（content 空时回退 thinking）、
//!    native_id 恒空、无 parent/sidechain；
//! 5. 坏行只递增 skipped/diagnostics，绝不吞消息；会话身份绝不臆造
//!    （session_native_id 恒 None + 固定一条 identity 诊断）；
//! 6. probe 对任意字节永不 panic；Ok 时 confidence 非 Ambiguous 且 variant 恒为自身。
//!
//! 另含 golden fixture 的 seeded 确定性变异（截断 / 插入 / 删除 / 翻转 / 拆行 /
//! 乱序行）语料：parse 永不 panic——Ok 则消息字段合法（span 界内且回切源行、
//! committed==emit、正文非空），Err 则 recoverable 由上层回滚；变异源字节前后
//! 不变（RFC-0002 §7 只读契约，经 testkit `assert_read_only` 守护）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表；断言信息一律携带
//! seed，失败可用该 seed 单独重放；不落盘、不联网。

use std::panic::{AssertUnwindSafe, catch_unwind};

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_antigravity::AntigravityAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::{Value, json};

const VARIANT_ID: &str = "antigravity/transcript-jsonl-v1";
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
    "step 记录自检",
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
    r#"{"step_index":3,"source":"MODEL","content":"torn"#,
    "{ not json at all",
    "]]]",
    "\"unterminated string",
    "42 trailing garbage }",
];

/// 形状合法（`is_rfc3339` 只查形状）的时间戳池。其中 `2026-13-40T99:99:99Z`
/// 语义越界但形状合法——故意收录，钉住"形状检查而非范围校验"的口径。
const VALID_TS: [&str; 6] = [
    "2026-07-03T13:22:16Z",
    "2026-07-03T13:22:16.5Z",
    "2026-07-03T13:22:16+08:00",
    "2026-07-03T13:22:16.123456z",
    "2026-13-40T99:99:99Z",
    "2026-07-03T13:22:16-05:30",
];

/// 形状非法的时间戳池：无时区 / 小写 t / 空格 / 纯文本 / 空串——全部落到 None。
const INVALID_TS: [&str; 5] = [
    "not-a-timestamp",
    "2026-07-03T13:22:16",
    "2026-07-03t13:22:16Z",
    "2026-07-03 13:22:16Z",
    "",
];

/// 一条预期产出的消息：角色、正文、时间戳与源记录行（span 回切对照物）。
struct ExpectedMessage {
    role: String,
    text: String,
    timestamp: Option<String>,
    line: String,
}

/// 一个生成的 step 流用例：快照字节 + 全部预期值 + 语料覆盖度标志。
struct Case {
    bytes: Vec<u8>,
    expected: Vec<ExpectedMessage>,
    malformed: usize,
    saw_thinking_fallback: bool,
    saw_invalid_ts: bool,
    saw_history_skip: bool,
}

/// step 的 content 形态。
enum StepContent {
    /// 字符串 content——正文直接取它。
    Str(String),
    /// 非字符串（数字/对象/数组）——`as_str` 取不到，回退 thinking。
    NonString(Value),
    /// 无 content 字段。
    Absent,
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

/// 一条 conversation step 的 ground truth 正文：content 非空取 content，
/// 否则 thinking 非空取 thinking，否则不产出消息（与生产一致）。
fn step_text(content: &StepContent, thinking: Option<&str>) -> Option<String> {
    let content_text = match content {
        StepContent::Str(s) => s.clone(),
        StepContent::NonString(_) | StepContent::Absent => String::new(),
    };
    if !content_text.trim().is_empty() {
        Some(content_text)
    } else {
        thinking
            .filter(|t| !t.trim().is_empty())
            .map(str::to_string)
    }
}

fn render_step(
    step_index: u64,
    source: Option<&str>,
    ty: Option<&str>,
    created_at: Option<&str>,
    content: &StepContent,
    thinking: Option<&str>,
) -> String {
    let mut record = json!({
        "step_index": step_index,
        "status": "DONE",
    });
    if let Some(s) = source {
        record["source"] = json!(s);
    }
    if let Some(t) = ty {
        record["type"] = json!(t);
    }
    if let Some(ts) = created_at {
        record["created_at"] = json!(ts);
    }
    match content {
        StepContent::Str(s) => record["content"] = json!(s),
        StepContent::NonString(v) => record["content"] = v.clone(),
        StepContent::Absent => {}
    }
    if let Some(t) = thinking {
        record["thinking"] = json!(t);
    }
    record.to_string()
}

fn build_case(seed: u64, with_big_field: bool) -> Case {
    let mut rng = XorShift64Star::new(seed);
    let mut expected: Vec<ExpectedMessage> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();
    let mut malformed = 0usize;
    let mut saw_thinking_fallback = false;
    let mut saw_invalid_ts = false;
    let mut saw_history_skip = false;

    let line_count = 8 + rng.below(28);
    for i in 0..line_count {
        let roll = rng.next_u64() % 100;
        let (record, maybe_msg) = if with_big_field && i == 0 {
            let record = render_step(
                i as u64,
                Some("USER_EXPLICIT"),
                Some("USER_INPUT"),
                Some("2026-07-03T13:22:14Z"),
                &StepContent::Str(big_text()),
                None,
            );
            (
                record,
                Some((
                    "user".to_string(),
                    big_text(),
                    Some("2026-07-03T13:22:14Z".to_string()),
                )),
            )
        } else if roll < 45 {
            // 会话 step：USER_EXPLICIT → user，MODEL → assistant。
            let source = if rng.chance(1, 2) {
                "USER_EXPLICIT"
            } else {
                "MODEL"
            };
            let role = if source == "USER_EXPLICIT" {
                "user"
            } else {
                "assistant"
            };
            let ty = if rng.chance(3, 4) {
                "USER_INPUT"
            } else {
                "PLANNER_RESPONSE"
            };
            let (created_at, ts_valid) = if rng.chance(2, 3) {
                (Some(rng.pick(&VALID_TS)), true)
            } else {
                (Some(rng.pick(&INVALID_TS)), false)
            };
            saw_invalid_ts |= !ts_valid;
            let content = match rng.below(10) {
                0..=6 => StepContent::Str(gen_text(&mut rng)),
                7 => StepContent::NonString(json!({"unexpected": "shape"})),
                8 => StepContent::Absent,
                _ => StepContent::NonString(json!(42)),
            };
            let thinking = if rng.chance(1, 3) {
                Some(gen_text(&mut rng))
            } else {
                None
            };
            let record = render_step(
                i as u64,
                Some(source),
                Some(ty),
                created_at,
                &content,
                thinking.as_deref(),
            );
            let msg = step_text(&content, thinking.as_deref()).map(|text| {
                if thinking.is_some()
                    && matches!(content, StepContent::Absent | StepContent::NonString(_))
                {
                    saw_thinking_fallback = true;
                }
                (
                    role.to_string(),
                    text,
                    created_at.filter(|_| ts_valid).map(str::to_string),
                )
            });
            (record, msg)
        } else if roll < 60 {
            // SYSTEM step（含未知 source）：绝不产出消息。
            let record = render_step(
                i as u64,
                Some("SYSTEM"),
                Some("CONTEXT_DUMP"),
                Some("2026-07-03T13:22:15Z"),
                &StepContent::Str(gen_text(&mut rng)),
                None,
            );
            (record, None)
        } else if roll < 70 {
            // MODEL + CONVERSATION_HISTORY：上下文转储，绝不产出消息。
            saw_history_skip = true;
            let record = render_step(
                i as u64,
                Some("MODEL"),
                Some("CONVERSATION_HISTORY"),
                Some("2026-07-03T13:22:15Z"),
                &StepContent::Str(gen_text(&mut rng)),
                None,
            );
            (record, None)
        } else if roll < 76 {
            // 会话 step 但正文与 thinking 全空：静默略过，不计 skipped。
            let record = render_step(
                i as u64,
                Some("MODEL"),
                Some("PLANNER_RESPONSE"),
                None,
                &StepContent::Absent,
                Some("   "),
            );
            (record, None)
        } else if roll < 82 {
            // 缺失 source 的 step：非会话，静默略过。
            let record = render_step(
                i as u64,
                None,
                Some("USER_INPUT"),
                None,
                &StepContent::Str(gen_text(&mut rng)),
                None,
            );
            (record, None)
        } else if roll < 92 {
            malformed += 1;
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
        let record = render_step(
            999,
            Some("USER_EXPLICIT"),
            Some("USER_INPUT"),
            Some("2026-07-03T13:22:14Z"),
            &StepContent::Str("forced valid record".to_string()),
            None,
        );
        expected.push(ExpectedMessage {
            role: "user".to_string(),
            text: "forced valid record".to_string(),
            timestamp: Some("2026-07-03T13:22:14Z".to_string()),
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
        malformed,
        saw_thinking_fallback,
        saw_invalid_ts,
        saw_history_skip,
    }
}

fn parse_case(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = AntigravityAdapter::new()
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

/// 性质 1：每条消息的 span 切回快照字节 == 其源 step 行（去行尾），
/// 对任意 Unicode 内容、混合行尾与大字段均成立。
#[test]
fn prop_span_roundtrips_to_source_step_line() {
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
                "seed={seed} seq={}: span 切片必须逐字节等于源 step 行（去行尾）",
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

/// 性质 4：role / text / timestamp 相对 ground truth 原样透传；native_id 恒空
/// （step_index 是文件内序号，不是跨文档 id）、无 parent、无 sidechain。
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
                "seed={seed} seq={seq}: 文本必须原样抽取（content 优先、thinking 回退）"
            );
            assert_eq!(
                got.timestamp, want.timestamp,
                "seed={seed} seq={seq}: timestamp 必须等于通过 is_rfc3339 的 created_at"
            );
            assert_eq!(
                got.native_id, "",
                "seed={seed} seq={seq}: antigravity 无原生消息 id，native_id 恒空"
            );
            assert_eq!(
                got.parent_native_id, None,
                "seed={seed} seq={seq}: antigravity 无 threading 边"
            );
            assert!(
                !got.is_sidechain,
                "seed={seed} seq={seq}: antigravity 无 sidechain"
            );
        }
    });
}

/// 性质 5：坏行只递增 skipped/diagnostics，绝不吞消息；会话身份绝不臆造
/// （session_native_id 恒 None、provider_session_id 恒 Missing），
/// diagnostics = 坏行数 + 固定 1 条 identity 说明。
#[test]
fn prop_malformed_lines_only_skip_and_identity_never_fabricated() {
    for_each_seed(|seed, case| {
        let (report, captured) = parse_case(seed, &case.bytes);
        assert_eq!(
            report.skipped, case.malformed,
            "seed={seed}: skipped 必须恰等于注入的坏行数"
        );
        assert_eq!(
            report.diagnostics.len(),
            case.malformed + 1,
            "seed={seed}: 诊断数必须 = 坏行数 + 固定 identity 说明"
        );
        assert_eq!(
            captured.len(),
            case.expected.len(),
            "seed={seed}: 坏行不得吞掉或伪造任何消息"
        );
        assert_eq!(
            report.session_native_id, None,
            "seed={seed}: transcript 内无会话 id，绝不臆造"
        );
        assert_eq!(
            report.session_observation.provider_session_id,
            MetadataResolution::Missing,
            "seed={seed}: provider_session_id 必须保持 Missing"
        );
        assert!(
            !report.session_observation.multi_session,
            "seed={seed}: 无会话 id 时 multi_session 必须为 false"
        );
    });
}

/// 语料覆盖度：64 个固定种子必须实际exercise过 thinking 回退、非法时间戳、
/// CONVERSATION_HISTORY 跳过与坏行——防止生成器退化成空转语料。
#[test]
fn prop_corpus_coverage_is_not_degenerate() {
    let mut saw_thinking = false;
    let mut saw_invalid_ts = false;
    let mut saw_history = false;
    let mut saw_malformed = false;
    for (i, seed) in fixed_seeds().iter().copied().enumerate() {
        let case = build_case(seed, i == 0);
        saw_thinking |= case.saw_thinking_fallback;
        saw_invalid_ts |= case.saw_invalid_ts;
        saw_history |= case.saw_history_skip;
        saw_malformed |= case.malformed > 0;
        assert!(
            !case.expected.is_empty(),
            "seed={seed}: 每个用例必须至少含一条有效消息"
        );
    }
    assert!(
        saw_thinking && saw_invalid_ts && saw_history && saw_malformed,
        "生成器语料退化：thinking={saw_thinking} invalid_ts={saw_invalid_ts} \
         history={saw_history} malformed={saw_malformed}"
    );
}

/// 只读契约：合成语料的 probe 与 parse 前后字节长度与 BLAKE3 指纹不变
/// （RFC-0002 §7 的可执行守护）。
#[test]
fn prop_probe_and_parse_are_read_only() {
    for_each_seed(|seed, case| {
        let report = assert_read_only(&case.bytes, |src| {
            let mut sink = CollectingSink::default();
            AntigravityAdapter::new().parse(src, &mut sink)
        })
        .unwrap_or_else(|e| panic!("seed={seed}: 合成流 parse 失败：{e}"));
        assert!(report.committed > 0, "seed={seed}: 合成流必须产出消息");
        let _ = assert_read_only(&case.bytes, |src| AntigravityAdapter::new().probe(src));
    });
}

/// probe 对任意字节永不 panic：纯随机 / 随机 ASCII 文本行 / 随机 JSON 状行 /
/// golden 随机截断。Ok 时 confidence 非 Ambiguous 且 variant 恒为自身。
#[test]
fn prop_probe_never_panics_on_arbitrary_bytes() {
    let adapter = AntigravityAdapter::new();
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
                            r#"{{"step_index":1,"source":"{}"}}"#,
                            rng.pick(&["USER_EXPLICIT", "MODEL", "SYSTEM", "garbage"])
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
        let adapter = AntigravityAdapter::new();
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
/// 到完整源行、正文非空。同时 probe 变异字节不 panic，且源字节在 parse 前后
/// 不变（RFC-0002 §7）。
#[test]
fn prop_golden_mutations_never_panic_and_output_stays_legal() {
    let fixture = std::fs::read(FIXTURE_PATH).expect("read golden fixture");
    let adapter = AntigravityAdapter::new();

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
                // span 回切：必须指向一条完整源行（去行尾），且是完整 JSON 记录。
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
                // span 指向的行必须与消息自洽：消息正是从该行发出的，因此
                // source 决定角色、CONVERSATION_HISTORY 绝不产出、正文必须等于
                // 该行的 content（空则 thinking）。变异可以删掉 step_index——
                // adapter 按契约不依赖它解析——但删不掉这份同源自洽。
                let source = rec.get("source").and_then(Value::as_str);
                let expected_source = if m.role == "user" {
                    "USER_EXPLICIT"
                } else {
                    "MODEL"
                };
                assert_eq!(
                    source,
                    Some(expected_source),
                    "seed={seed} op={op}: seq={} span 行的 source 必须与角色一致",
                    m.seq
                );
                assert_ne!(
                    rec.get("type").and_then(Value::as_str),
                    Some("CONVERSATION_HISTORY"),
                    "seed={seed} op={op}: seq={} CONVERSATION_HISTORY 行绝不产出消息",
                    m.seq
                );
                let content = rec.get("content").and_then(Value::as_str).unwrap_or("");
                let thinking = rec.get("thinking").and_then(Value::as_str).unwrap_or("");
                let expected_text = if !content.trim().is_empty() {
                    content
                } else {
                    thinking
                };
                assert_eq!(
                    m.text, expected_text,
                    "seed={seed} op={op}: seq={} 正文必须等于 span 行的 content（空则 thinking）",
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
