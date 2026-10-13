//! Hermes adapter（`hermes/session-json-v1`）的确定性 property 套件。
//!
//! Hermes 源是整份 JSON（非逐行），与 JSONL 系 provider 的结构不同：
//! 无字节 span（`span: None` 恒成立）、无 recoverable skip（整份解析要么 Ok
//! 要么 StructuralFatal）。用固定种子生成随机 `session_<id>.json`
//! （session_id / session_start / 混排角色的 messages），逐条验证：
//!
//! 1. span 恒 None（whole-file JSON 无法归因行内字节坐标）；
//! 2. seq 从 0 连续，committed == emit 数 == ground truth 消息数；
//! 3. 确定性：同一字节两次解析，事件流与报告完全一致；
//! 4. 元数据透传：role/text 原样（reasoning 折叠进 [thinking] 块）、
//!    timestamp == 消息级字符串或 session_start 回退、native_id 恒空；
//! 5. 会话身份：session_native_id == 顶层 session_id（trim 后），缺席则 Missing；
//! 6. probe 对任意字节永不 panic：Ok 时恒 Confirmed 且 variant 为自身，
//!    Err 恒为 AmbiguousVariant（hermes probe 的全部拒绝路径）；
//! 7. golden fixture 的 seeded 确定性变异下 parse 永不 panic：Ok 则消息字段合法
//!    （committed==emit、正文非空、span 恒 None），Err 恒为 StructuralFatal；
//!    变异源字节前后不变（RFC-0002 §7，经 testkit `assert_read_only`）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表；断言信息一律携带
//! seed，失败可用该 seed 单独重放；不落盘、不联网。

use std::panic::{AssertUnwindSafe, catch_unwind};

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter, ProviderError,
};
use agent_session_grep_provider_hermes::OpenHermesAdapter;
use agent_session_grep_testkit::assert_read_only;
use serde_json::{Value, json};

const VARIANT_ID: &str = "hermes/session-json-v1";
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.json");

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
    "hermes 会话自检",
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

/// 一条预期产出的消息：角色、折叠后的正文与时间戳。
struct ExpectedMessage {
    role: String,
    text: String,
    timestamp: Option<String>,
}

/// 一个生成的 Hermes session 用例：快照字节 + 全部预期值 + 语料覆盖度标志。
struct Case {
    bytes: Vec<u8>,
    expected: Vec<ExpectedMessage>,
    session_id: Option<String>,
    saw_thinking: bool,
    saw_ts_fallback: bool,
    saw_ts_number: bool,
    saw_empty_skip: bool,
    saw_role_skip: bool,
}

fn gen_text(rng: &mut XorShift64Star) -> String {
    let n = 1 + rng.below(3);
    (0..n)
        .map(|_| rng.pick(&TEXT_POOL))
        .collect::<Vec<_>>()
        .join(" ")
}

/// ~256 KiB 大字段：多字节图样重复，压大行路径与 UTF-8 处理。
fn big_text() -> String {
    let unit = "大字段填充🚀0123456789abcdef ";
    let mut s = String::with_capacity(262_144 + unit.len());
    while s.len() < 262_144 {
        s.push_str(unit);
    }
    s
}

fn build_case(seed: u64, with_big_field: bool) -> Case {
    let mut rng = XorShift64Star::new(seed);
    let mut expected: Vec<ExpectedMessage> = Vec::new();
    let mut saw_thinking = false;
    let mut saw_ts_fallback = false;
    let mut saw_ts_number = false;
    let mut saw_empty_skip = false;
    let mut saw_role_skip = false;

    // session_id：75% 存在（其中 1/8 为空白 → 视同缺席）。
    let session_id = match rng.below(8) {
        0..=5 => Some(format!("hermes-sess-{seed:016x}")),
        6 => Some("   ".to_string()),
        _ => None,
    };
    let expected_session_id = session_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());
    let session_start = rng
        .chance(2, 3)
        .then(|| "2026-04-18T04:53:25.274422".to_string());

    let n = 1 + rng.below(8);
    let mut messages: Vec<Value> = Vec::with_capacity(n);
    for i in 0..n {
        let role = match rng.below(20) {
            0..=6 => "user",
            7..=13 => "assistant",
            14..=16 => "system",
            17..=18 => "tool",
            _ => "",
        };
        let content: Option<String> = if with_big_field && i == 0 {
            Some(big_text())
        } else {
            match rng.below(10) {
                0..=6 => Some(gen_text(&mut rng)),
                7..=8 => Some("   ".to_string()),
                _ => None,
            }
        };
        let reasoning: Option<String> = match rng.below(10) {
            0..=2 => Some(gen_text(&mut rng)),
            3 => Some("   ".to_string()),
            _ => None,
        };
        let timestamp: Option<Value> = match rng.below(10) {
            0..=3 => Some(json!("2026-04-18T04:53:26")),
            4 => {
                saw_ts_number = true;
                Some(json!(1_772_000_000))
            }
            _ => None,
        };

        // ground truth：与生产 parse 同口径。
        let conversational = matches!(role, "user" | "assistant");
        let content_text = content.as_deref().unwrap_or("");
        let reasoning_text = reasoning.as_deref().unwrap_or("");
        if conversational && !content_text.trim().is_empty() {
            let text = if !reasoning_text.trim().is_empty() {
                saw_thinking = true;
                format!("[thinking]\n{reasoning_text}\n[/thinking]\n{content_text}")
            } else {
                content_text.to_string()
            };
            let ts = timestamp
                .as_ref()
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| session_start.clone());
            if timestamp.is_some() && timestamp.as_ref().and_then(Value::as_str).is_none() {
                saw_ts_fallback = true;
            }
            expected.push(ExpectedMessage {
                role: role.to_string(),
                text,
                timestamp: ts,
            });
        } else if conversational {
            saw_empty_skip = true;
        } else {
            saw_role_skip = true;
        }

        let mut msg = json!({"role": role});
        if let Some(c) = &content {
            msg["content"] = json!(c);
        }
        if let Some(r) = &reasoning {
            msg["reasoning"] = json!(r);
        }
        if let Some(t) = &timestamp {
            msg["timestamp"] = t.clone();
        }
        messages.push(msg);
    }

    // 属性前提是"存在有效消息"；极端种子下若一条未生成则强制补一条。
    if expected.is_empty() {
        let msg = json!({"role": "user", "content": "forced valid record"});
        expected.push(ExpectedMessage {
            role: "user".to_string(),
            text: "forced valid record".to_string(),
            timestamp: session_start.clone(),
        });
        messages.push(msg);
    }

    let mut doc = json!({
        "model": "hermes-3-synthetic",
        "base_url": "http://localhost:11434",
        "messages": messages,
    });
    if let Some(id) = &session_id {
        doc["session_id"] = json!(id);
    }
    if let Some(ts) = &session_start {
        doc["session_start"] = json!(ts);
    }
    let bytes = serde_json::to_vec_pretty(&doc).expect("serialize synthetic hermes doc");

    Case {
        bytes,
        expected,
        session_id: expected_session_id,
        saw_thinking,
        saw_ts_fallback,
        saw_ts_number,
        saw_empty_skip,
        saw_role_skip,
    }
}

fn parse_case(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = OpenHermesAdapter::new()
        .parse(bytes, &mut sink)
        .unwrap_or_else(|e| panic!("seed={seed}: 合法生成的 hermes 文档 parse 失败：{e}"));
    (report, sink.messages)
}

/// 逐固定种子运行 body；index 0 的迭代携带 ~256 KiB 大字段。
fn for_each_seed(mut body: impl FnMut(u64, &Case)) {
    for (idx, &seed) in fixed_seeds().iter().enumerate() {
        let case = build_case(seed, idx == 0);
        body(seed, &case);
    }
}

/// 性质 1：whole-file JSON 没有行内字节坐标——所有消息 span 恒 None。
#[test]
fn prop_spans_are_always_none() {
    for_each_seed(|seed, case| {
        let (_, captured) = parse_case(seed, &case.bytes);
        for got in &captured {
            assert_eq!(
                got.span, None,
                "seed={seed} seq={}: hermes 为整份 JSON，不得归因行内 span",
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

/// 性质 4：role / text（reasoning 折叠进 [thinking] 块）/ timestamp
/// （消息级字符串优先、session_start 回退）相对 ground truth 原样透传；
/// native_id 恒空、无 parent、无 sidechain。
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
                "seed={seed} seq={seq}: 文本必须等于 content + reasoning 折叠结果"
            );
            assert_eq!(
                got.timestamp, want.timestamp,
                "seed={seed} seq={seq}: timestamp 必须等于消息级字符串或 session_start 回退"
            );
            assert_eq!(
                got.native_id, "",
                "seed={seed} seq={seq}: hermes 无原生消息 id，native_id 恒空"
            );
            assert_eq!(
                got.parent_native_id, None,
                "seed={seed} seq={seq}: hermes 无 threading 边"
            );
            assert!(
                !got.is_sidechain,
                "seed={seed} seq={seq}: hermes 无 sidechain"
            );
        }
    });
}

/// 性质 5：会话身份——session_native_id == 顶层 session_id（trim 后），
/// 缺席/空白时保持 Missing，绝不臆造。整份 JSON 无 recoverable skip：
/// skipped 恒 0、diagnostics 恒空。
#[test]
fn prop_session_identity_and_zero_skipped() {
    for_each_seed(|seed, case| {
        let (report, _) = parse_case(seed, &case.bytes);
        assert_eq!(
            report.session_native_id, case.session_id,
            "seed={seed}: session_native_id 必须等于顶层 session_id（trim 后）"
        );
        match case.session_id.as_deref() {
            Some(id) => assert_eq!(
                report.session_observation.provider_session_id,
                MetadataResolution::Resolved(id.to_string()),
                "seed={seed}: 有会话 id 时 provider_session_id 必须 Resolved"
            ),
            None => assert_eq!(
                report.session_observation.provider_session_id,
                MetadataResolution::Missing,
                "seed={seed}: 无会话 id 时 provider_session_id 必须 Missing"
            ),
        }
        assert_eq!(
            report.skipped, 0,
            "seed={seed}: 整份 JSON 无 recoverable skip"
        );
        assert!(
            report.diagnostics.is_empty(),
            "seed={seed}: 合法文档不得产生诊断"
        );
    });
}

/// 语料覆盖度：64 个固定种子必须实际exercise过 thinking 折叠、时间戳回退、
/// 数字时间戳、空 content 跳过、非会话角色跳过——防止生成器退化成空转语料。
#[test]
fn prop_corpus_coverage_is_not_degenerate() {
    let mut saw_thinking = false;
    let mut saw_fallback = false;
    let mut saw_number = false;
    let mut saw_empty = false;
    let mut saw_role = false;
    for (i, seed) in fixed_seeds().iter().copied().enumerate() {
        let case = build_case(seed, i == 0);
        saw_thinking |= case.saw_thinking;
        saw_fallback |= case.saw_ts_fallback;
        saw_number |= case.saw_ts_number;
        saw_empty |= case.saw_empty_skip;
        saw_role |= case.saw_role_skip;
        assert!(
            !case.expected.is_empty(),
            "seed={seed}: 每个用例必须至少含一条有效消息"
        );
    }
    assert!(
        saw_thinking && saw_fallback && saw_number && saw_empty && saw_role,
        "生成器语料退化：thinking={saw_thinking} fallback={saw_fallback} \
         number={saw_number} empty={saw_empty} role={saw_role}"
    );
}

/// 只读契约：合成语料的 probe 与 parse 前后字节长度与 BLAKE3 指纹不变
/// （RFC-0002 §7 的可执行守护）。
#[test]
fn prop_probe_and_parse_are_read_only() {
    for_each_seed(|seed, case| {
        let report = assert_read_only(&case.bytes, |src| {
            let mut sink = CollectingSink::default();
            OpenHermesAdapter::new().parse(src, &mut sink)
        })
        .unwrap_or_else(|e| panic!("seed={seed}: 合成文档 parse 失败：{e}"));
        assert!(report.committed > 0, "seed={seed}: 合成文档必须产出消息");
        let _ = assert_read_only(&case.bytes, |src| OpenHermesAdapter::new().probe(src));
    });
}

/// probe 对任意字节永不 panic：纯随机 / 随机 ASCII 文本 / 随机 JSON 状文档 /
/// golden 随机截断。hermes probe 的全部拒绝路径都是 AmbiguousVariant——
/// Ok 时恒 Confirmed 且 variant 为自身。
#[test]
fn prop_probe_never_panics_on_arbitrary_bytes() {
    let adapter = OpenHermesAdapter::new();
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
                    // 随机 JSON 状文档：messages 数组 / session_id 混搭。
                    let mut s = String::new();
                    s.push_str(r#"{"session_id": "fuzz"#);
                    let n = rng.below(4);
                    for _ in 0..n {
                        s.push_str(&format!(
                            r#", "messages": [{{"role": "{}", "content": "x"}}]"#,
                            rng.pick(&["user", "assistant", "system", ""])
                        ));
                    }
                    s.push('}');
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
                    assert_eq!(
                        r.confidence,
                        Confidence::Confirmed,
                        "seed={seed} k={k}: hermes probe Ok 时恒为 Confirmed"
                    );
                    assert_eq!(
                        r.variant_id, VARIANT_ID,
                        "seed={seed} k={k}: probe 必须报告自身 variant"
                    );
                }
                Ok(Err(e)) => assert!(
                    matches!(e, ProviderError::AmbiguousVariant(_)),
                    "seed={seed} k={k}: hermes probe 的拒绝必须是 AmbiguousVariant，实际 {e:?}"
                ),
                Err(payload) => panic!(
                    "seed={seed} k={k}: probe 在 {} 字节任意输入上 panic: {payload:?}",
                    bytes.len()
                ),
            }
        }
    }
}

/// 合成语料上的 probe：不 panic、两次调用结果一致、恒 Ok(Confirmed) 且
/// variant 为自身（合成文档必有非空 messages 数组）。
#[test]
fn prop_probe_on_generated_docs_confirms_own_variant() {
    for_each_seed(|seed, case| {
        let adapter = OpenHermesAdapter::new();
        let a = adapter.probe(&case.bytes);
        let b = adapter.probe(&case.bytes);
        assert_eq!(a, b, "seed={seed}: probe 两次调用必须确定一致");
        let r = a.unwrap_or_else(|e| panic!("seed={seed}: 合成文档 probe 必须成功：{e}"));
        assert_eq!(
            r.confidence,
            Confidence::Confirmed,
            "seed={seed}: 必须 Confirmed"
        );
        assert_eq!(
            r.variant_id, VARIANT_ID,
            "seed={seed}: probe 必须报告自身 variant"
        );
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
            // 拆行：文档内随机位置插入换行（pretty-printed 多行 JSON）。
            let pos = rng.below(out.len());
            out.insert(pos, b'\n');
        }
        _ => {
            // 乱序行：随机交换两行（pretty-printed JSON 的行级重排）。
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

/// 变异语料上的 parse：永不 panic。Err 恒为 StructuralFatal（hermes 整份解析
/// 没有 recoverable 分支——上层按整体回滚）；Ok 则绝不 partial commit——
/// committed == emit 数、seq 连续、span 恒 None、正文非空、角色合法。
/// 同时 probe 变异字节不 panic（Ok 恒 Confirmed、Err 恒 AmbiguousVariant），
/// 且源字节在 parse 前后不变（RFC-0002 §7）。
#[test]
fn prop_golden_mutations_never_panic_and_output_stays_legal() {
    let fixture = std::fs::read(FIXTURE_PATH).expect("read golden fixture");
    let adapter = OpenHermesAdapter::new();

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
                Ok(Err(e)) => {
                    assert!(
                        matches!(e, ProviderError::StructuralFatal(_)),
                        "seed={seed} op={op}: hermes parse 的失败必须是 StructuralFatal，实际 {e:?}"
                    );
                    continue;
                }
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
                assert_eq!(
                    m.span, None,
                    "seed={seed} op={op}: seq={} hermes 不得归因行内 span",
                    m.seq
                );
            }

            // probe 同样必须对变异字节不 panic。
            let probed = catch_unwind(AssertUnwindSafe(|| adapter.probe(&mutated)));
            match probed {
                Ok(Ok(r)) => {
                    assert_eq!(
                        r.confidence,
                        Confidence::Confirmed,
                        "seed={seed} op={op}: hermes probe Ok 时恒为 Confirmed"
                    );
                    assert_eq!(
                        r.variant_id, VARIANT_ID,
                        "seed={seed} op={op}: probe 必须报告自身 variant"
                    );
                }
                Ok(Err(e)) => assert!(
                    matches!(e, ProviderError::AmbiguousVariant(_)),
                    "seed={seed} op={op}: hermes probe 的拒绝必须是 AmbiguousVariant，实际 {e:?}"
                ),
                Err(payload) => {
                    panic!("seed={seed} op={op}: probe 在变异输入上 panic: {payload:?}")
                }
            }
        }
    }
}
