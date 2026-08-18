//! ClaudeCodeAdapter 的确定性 property 套件：seeded 随机 transcript 与解析
//! 输出之间的不变量（span round-trip / seq 连续 / 确定性 / 元数据透传 /
//! 坏行只降级不中止）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表。断言信息
//! 一律携带 seed，失败可用该 seed 单独重放；不落盘、不联网。

use agent_session_grep_ports::{CanonicalEventSink, MessageEvent, ParseReport, ProviderAdapter};
use agent_session_grep_provider_claude::ClaudeCodeAdapter;
use serde_json::json;

/// 固定种子表（黄金比例奇数 0x9e3779b97f4a7c15 的 1..=64 倍，mod 2^64）：
/// 64 次迭代全部确定复现；index 0 的迭代额外携带 ~256 KiB 大字段。
const SEEDS: [u64; 64] = [
    0x9e3779b97f4a7c15,
    0x3c6ef372fe94f82a,
    0xdaa66d2c7ddf743f,
    0x78dde6e5fd29f054,
    0x1715609f7c746c69,
    0xb54cda58fbbee87e,
    0x538454127b096493,
    0xf1bbcdcbfa53e0a8,
    0x8ff34785799e5cbd,
    0x2e2ac13ef8e8d8d2,
    0xcc623af8783354e7,
    0x6a99b4b1f77dd0fc,
    0x08d12e6b76c84d11,
    0xa708a824f612c926,
    0x454021de755d453b,
    0xe3779b97f4a7c150,
    0x81af155173f23d65,
    0x1fe68f0af33cb97a,
    0xbe1e08c47287358f,
    0x5c55827df1d1b1a4,
    0xfa8cfc37711c2db9,
    0x98c475f0f066a9ce,
    0x36fbefaa6fb125e3,
    0xd5336963eefba1f8,
    0x736ae31d6e461e0d,
    0x11a25cd6ed909a22,
    0xafd9d6906cdb1637,
    0x4e115049ec25924c,
    0xec48ca036b700e61,
    0x8a8043bceaba8a76,
    0x28b7bd766a05068b,
    0xc6ef372fe94f82a0,
    0x6526b0e96899feb5,
    0x035e2aa2e7e47aca,
    0xa195a45c672ef6df,
    0x3fcd1e15e67972f4,
    0xde0497cf65c3ef09,
    0x7c3c1188e50e6b1e,
    0x1a738b426458e733,
    0xb8ab04fbe3a36348,
    0x56e27eb562eddf5d,
    0xf519f86ee2385b72,
    0x935172286182d787,
    0x3188ebe1e0cd539c,
    0xcfc0659b6017cfb1,
    0x6df7df54df624bc6,
    0x0c2f590e5eacc7db,
    0xaa66d2c7ddf743f0,
    0x489e4c815d41c005,
    0xe6d5c63adc8c3c1a,
    0x850d3ff45bd6b82f,
    0x2344b9addb213444,
    0xc17c33675a6bb059,
    0x5fb3ad20d9b62c6e,
    0xfdeb26da5900a883,
    0x9c22a093d84b2498,
    0x3a5a1a4d5795a0ad,
    0xd8919406d6e01cc2,
    0x76c90dc0562a98d7,
    0x15008779d57514ec,
    0xb338013354bf9101,
    0x516f7aecd40a0d16,
    0xefa6f4a65354892b,
    0x8dde6e5fd29f0540,
];

/// xorshift64*（Marsaglia）：约 15 行的本地确定性 PRNG，状态非零。
struct XorShift64Star(u64);

impl XorShift64Star {
    fn new(seed: u64) -> Self {
        // 全零状态会让 xorshift 永远输出 0——用固定奇数常量兜住。
        XorShift64Star(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// [0, n) 的伪均匀整数；测试输入多样性场景下取模偏差可忽略。
    fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// Unicode 文本池：CJK / 日韩 / emoji / RTL（阿拉伯文、带附加符希伯来文）/
/// 4 字节数学字母 / 内嵌换行与制表 / 引号反斜杠 / 零宽字符 / 空串。
const TEXT_POOL: &[&str] = &[
    "plain ascii text",
    "会话历史检索引擎",
    "こんにちは、世界",
    "안녕하세요",
    "🚀🌏🧪✨",
    "مرحبا بالعالم",
    "שָׁלוֹם עוֹלָם",
    "𝕌𝕟𝕚𝕔𝕠𝕕𝕖 mathematical",
    "tab\there\nand embedded newline",
    "quote\" back\\slash",
    "zero\u{200B}width",
    "",
];

/// 坏行池：截断对象 / 未闭合字符串 / 纯垃圾 / 括号错配，以及"合法 JSON 但
/// 不是记录对象"（数组、字符串、数字）——全部应走 record_recoverable 跳过。
const MALFORMED_POOL: &[&str] = &[
    r#"{"type":"user","message":"#,
    r#"{"type":"assistant","uuid":"unterminated"#,
    "not json at all",
    "{]",
    "[1,2,3]",
    r#""just a string""#,
    "42",
];

/// 生成器的 ground truth：独立于 parser 记录"每条有效消息应当以什么形态出现"。
#[derive(Debug)]
struct ExpectedMessage {
    native_id: String,
    parent_native_id: Option<String>,
    role: String,
    text: String,
    timestamp: Option<String>,
    is_sidechain: bool,
    /// 渲染后的源记录行（不含行尾符）——span round-trip 的对照物。
    line: String,
}

/// 一次迭代生成的完整 transcript 及其应然口径。
struct GeneratedTranscript {
    bytes: Vec<u8>,
    messages: Vec<ExpectedMessage>,
    /// 应计入 skipped 的行数（破损 JSON + 缺 `message` 体的对话记录）。
    skipped: usize,
    session_id: String,
}

/// 取一段随机 Unicode 文本；`large` 时拼出 ~256 KiB 多字节大字段。
fn make_text(rng: &mut XorShift64Star, large: bool) -> String {
    if large {
        let chunk = "大字段填充🚀0123456789abcdef";
        let mut s = String::with_capacity(262_144 + chunk.len());
        while s.len() < 262_144 {
            s.push_str(chunk);
        }
        return s;
    }
    let picks = rng.below(4) + 1;
    let mut parts = Vec::new();
    for _ in 0..picks {
        parts.push(TEXT_POOL[rng.below(TEXT_POOL.len() as u64) as usize]);
    }
    parts.join(" ")
}

/// 从种子构造随机 transcript：有效对话记录（随机角色/内容形态/threading/
/// sidechain）与坏行、非对话记录、空白行交错，行尾 LF/CRLF 混排，
/// 末行随机缺行尾符。返回字节与 ground truth。
fn build_transcript(seed: u64, with_large_field: bool) -> GeneratedTranscript {
    let mut rng = XorShift64Star::new(seed);
    let session_id = format!("prop-sess-{seed:016x}");
    let mut messages: Vec<ExpectedMessage> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();
    let mut skipped = 0usize;

    let line_count = 8 + rng.below(24);
    for i in 0..line_count {
        // 大字段迭代把首行强制为携带 ~256 KiB 文本的有效记录。
        let force_large_valid = with_large_field && i == 0;
        let roll = if force_large_valid { 0 } else { rng.below(100) };
        if roll < 55 {
            // —— 有效对话记录 ——
            let kind = ["user", "assistant", "system"][rng.below(3) as usize];
            let role_field = match rng.below(10) {
                0..=2 => "user",
                3..=5 => "assistant",
                6 => "system",
                7..=8 => "tool",
                // 空 role → parser 回退到顶层 type。
                _ => "",
            };
            let expected_role = if role_field.is_empty() {
                kind
            } else {
                role_field
            };
            let uuid = format!("prop-{seed:016x}-{i:04}");
            let parent = if !messages.is_empty() && rng.chance(60) {
                let idx = rng.below(messages.len() as u64) as usize;
                Some(messages[idx].native_id.clone())
            } else {
                None
            };
            let timestamp = if rng.chance(70) {
                Some(format!(
                    "2026-01-01T{:02}:{:02}:{:02}.{:03}Z",
                    rng.below(24),
                    rng.below(60),
                    rng.below(60),
                    rng.below(1000)
                ))
            } else {
                None
            };
            let sidechain = rng.chance(30);
            // content 两种形态：字符串，或 text 块与无 text 工具块混排的数组。
            let (content, text) = if force_large_valid || rng.chance(50) {
                let t = make_text(&mut rng, force_large_valid);
                (json!(t), t)
            } else {
                let block_count = rng.below(4);
                let mut blocks = Vec::new();
                let mut texts = Vec::new();
                for _ in 0..block_count {
                    if rng.chance(75) {
                        let t = make_text(&mut rng, false);
                        blocks.push(json!({"type": "text", "text": t.clone()}));
                        texts.push(t);
                    } else {
                        blocks.push(json!({
                            "type": "tool_use", "id": "toolu-prop", "name": "Synthetic", "input": {}
                        }));
                    }
                }
                (json!(blocks), texts.join("\n"))
            };
            let mut record = json!({
                "type": kind,
                "uuid": uuid,
                "parentUuid": parent,
                "isSidechain": sidechain,
                "sessionId": session_id,
                "message": {"role": role_field, "content": content},
            });
            if let Some(ts) = &timestamp {
                record["timestamp"] = json!(ts);
            }
            let line = serde_json::to_string(&record).expect("render valid record");
            messages.push(ExpectedMessage {
                native_id: uuid,
                parent_native_id: parent,
                role: expected_role.to_string(),
                text,
                timestamp,
                is_sidechain: sidechain,
                line: line.clone(),
            });
            rendered.push(line);
        } else if roll < 70 {
            // —— 坏行：应计 skipped ——
            skipped += 1;
            rendered
                .push(MALFORMED_POOL[rng.below(MALFORMED_POOL.len() as u64) as usize].to_string());
        } else if roll < 80 {
            // —— 对话类型但缺 message 体：record_recoverable，应计 skipped ——
            skipped += 1;
            let line = serde_json::to_string(&json!({
                "type": "user",
                "uuid": format!("prop-{seed:016x}-{i:04}-nomsg"),
                "sessionId": session_id,
            }))
            .expect("render no-message record");
            rendered.push(line);
        } else if roll < 92 {
            // —— 非对话记录：静默略过，不计 skipped ——
            let kind =
                ["summary", "file-history-snapshot", "x-future-record"][rng.below(3) as usize];
            let line = serde_json::to_string(&json!({
                "type": kind,
                "summary": "synthetic non-conversational record",
                "leafUuid": format!("prop-leaf-{i:04}"),
            }))
            .expect("render non-conversational record");
            rendered.push(line);
        } else {
            // —— 空白行：静默略过，但仍占字节偏移 ——
            rendered.push(if rng.chance(50) {
                String::new()
            } else {
                "   ".to_string()
            });
        }
    }

    // 属性 5 的前提是"存在有效记录"；极端种子下若一条未生成则强制补一条。
    if messages.is_empty() {
        let uuid = format!("prop-{seed:016x}-forced");
        let line = serde_json::to_string(&json!({
            "type": "user",
            "uuid": uuid,
            "parentUuid": null,
            "isSidechain": false,
            "sessionId": session_id,
            "message": {"role": "user", "content": "forced valid record"},
        }))
        .expect("render forced record");
        messages.push(ExpectedMessage {
            native_id: uuid,
            parent_native_id: None,
            role: "user".to_string(),
            text: "forced valid record".to_string(),
            timestamp: None,
            is_sidechain: false,
            line: line.clone(),
        });
        rendered.push(line);
    }

    // 渲染字节：逐行随机 LF / CRLF；末行 30% 概率不带行尾符。
    let mut bytes = Vec::new();
    let total = rendered.len();
    for (idx, line) in rendered.iter().enumerate() {
        bytes.extend_from_slice(line.as_bytes());
        if idx + 1 == total && rng.chance(30) {
            break;
        }
        bytes.extend_from_slice(if rng.chance(50) { b"\r\n" } else { b"\n" });
    }

    GeneratedTranscript {
        bytes,
        messages,
        skipped,
        session_id,
    }
}

/// 收集 emit 的消息事件（本地 helper，与单元测试同构）；派生 PartialEq
/// 供确定性属性做整体比较。
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

/// 解析生成的 transcript；含有效记录时 parse 绝不允许整体失败（属性 5 的一半）。
fn parse_transcript(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = ClaudeCodeAdapter::new()
        .parse(bytes, &mut sink)
        .unwrap_or_else(|e| panic!("seed={seed}: parse 在存在有效记录时整体失败：{e}"));
    (report, sink.messages)
}

/// 逐固定种子运行 body；index 0 的迭代携带 ~256 KiB 大字段。
fn for_each_seed(mut body: impl FnMut(u64, &GeneratedTranscript)) {
    for (idx, &seed) in SEEDS.iter().enumerate() {
        let case = build_transcript(seed, idx == 0);
        body(seed, &case);
    }
}

/// 属性 1：每条消息的 span 切回快照字节 == 其源记录行（去行尾），
/// 对任意 Unicode 内容、混合行尾与大字段均成立。
#[test]
fn prop_span_roundtrips_to_source_record() {
    for_each_seed(|seed, case| {
        let (_, captured) = parse_transcript(seed, &case.bytes);
        assert_eq!(
            captured.len(),
            case.messages.len(),
            "seed={seed}: 消息数必须等于 ground truth"
        );
        for (got, want) in captured.iter().zip(&case.messages) {
            let (start, end) = got
                .span
                .unwrap_or_else(|| panic!("seed={seed} seq={}: 消息必须携带 span", got.seq));
            let slice = &case.bytes[start as usize..end as usize];
            assert_eq!(
                slice,
                want.line.as_bytes(),
                "seed={seed} seq={}: span 切片必须逐字节等于源记录行（去行尾）",
                got.seq
            );
        }
    });
}

/// 属性 2：seq 从 0 连续，且 count == committed。
#[test]
fn prop_seq_contiguous_and_counts_committed() {
    for_each_seed(|seed, case| {
        let (report, captured) = parse_transcript(seed, &case.bytes);
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
            case.messages.len(),
            "seed={seed}: committed 必须等于 ground truth 有效消息数"
        );
    });
}

/// 属性 3：同一字节输入解析两次，事件流与报告完全一致（确定性）。
#[test]
fn prop_parse_is_deterministic() {
    for_each_seed(|seed, case| {
        let (report_a, captured_a) = parse_transcript(seed, &case.bytes);
        let (report_b, captured_b) = parse_transcript(seed, &case.bytes);
        assert_eq!(report_a, report_b, "seed={seed}: 两次解析的报告必须一致");
        assert_eq!(
            captured_a, captured_b,
            "seed={seed}: 两次解析收集的事件必须一致"
        );
    });
}

/// 属性 4（claude 专项）：native_id / parentUuid / role / 文本 / timestamp /
/// isSidechain 相对生成时的 ground truth 原样透传。
#[test]
fn prop_threading_metadata_survives_verbatim() {
    for_each_seed(|seed, case| {
        let (_, captured) = parse_transcript(seed, &case.bytes);
        assert_eq!(
            captured.len(),
            case.messages.len(),
            "seed={seed}: 消息数必须等于 ground truth"
        );
        for (got, want) in captured.iter().zip(&case.messages) {
            let seq = got.seq;
            assert_eq!(
                got.native_id, want.native_id,
                "seed={seed} seq={seq}: native_id 必须原样透传"
            );
            assert_eq!(
                got.parent_native_id, want.parent_native_id,
                "seed={seed} seq={seq}: parentUuid 必须原样透传"
            );
            assert_eq!(
                got.role, want.role,
                "seed={seed} seq={seq}: role 必须原样透传"
            );
            assert_eq!(
                got.text, want.text,
                "seed={seed} seq={seq}: 文本必须原样抽取"
            );
            assert_eq!(
                got.timestamp, want.timestamp,
                "seed={seed} seq={seq}: timestamp 必须原样透传"
            );
            assert_eq!(
                got.is_sidechain, want.is_sidechain,
                "seed={seed} seq={seq}: isSidechain 必须原样透传"
            );
        }
    });
}

/// 属性 5：坏行只递增 skipped/diagnostics，绝不吞消息、绝不中止解析；
/// sessionId 照常被提取。
#[test]
fn prop_malformed_lines_only_skip_never_abort() {
    for_each_seed(|seed, case| {
        let (report, captured) = parse_transcript(seed, &case.bytes);
        assert_eq!(
            report.skipped, case.skipped,
            "seed={seed}: skipped 必须恰等于注入的坏行数"
        );
        assert_eq!(
            report.diagnostics.len(),
            case.skipped,
            "seed={seed}: 每个坏行必须恰好留下一条诊断"
        );
        assert_eq!(
            captured.len(),
            case.messages.len(),
            "seed={seed}: 坏行不得吞掉或伪造任何消息"
        );
        assert_eq!(
            report.session_native_id.as_deref(),
            Some(case.session_id.as_str()),
            "seed={seed}: sessionId 必须被正常提取"
        );
    });
}
