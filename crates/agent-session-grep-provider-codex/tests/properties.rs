//! Codex adapter 的确定性 property 测试：用固定种子生成随机 rollout，
//! 逐条验证结构不变量。零新依赖——test-local xorshift64* PRNG（延续各
//! provider crate 测试各自持有 CollectingSink 的先例）。
//!
//! 失败信息一律携带 seed；复现方法：临时加一个测试调用
//! `run_case(<失败信息里的 seed>, false)`（大字段用例为 `true`）。
//!
//! 覆盖的六条性质（对应 golden-hardening 设计）：
//! 1. committed == 权威 `response_item/message` 条数——`event_msg` 镜像无论
//!    数量与穿插位置都不得改变计数（codex 关键性质：镜像不重复计数）；
//! 2. span 回切：每条产出消息的 span 切回快照字节等于其来源封套行；
//! 3. seq 从 0 连续；
//! 4. 确定性：同一字节两次解析，事件流与报告完全一致；
//! 5. session_native_id 等于生成的 session_meta session_id，缺席则 None；
//! 6. 损坏行只增加 skipped/diagnostics，绝不中断含合法记录的解析。

use agent_session_grep_ports::{CanonicalEventSink, MessageEvent, ProviderAdapter};
use agent_session_grep_provider_codex::CodexAdapter;
use serde_json::json;

/// 收集 emit 的消息事件；派生 PartialEq 以支撑"两次解析逐字段一致"断言。
#[derive(Default)]
struct CollectingSink {
    messages: Vec<Captured>,
}

#[derive(Debug, PartialEq, Eq)]
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

/// adapter 承认的对话角色（developer 是 Codex 特有的系统提示层）。
const ROLES: [&str; 4] = ["user", "assistant", "developer", "system"];

/// Unicode 文本池：CJK、emoji、RTL（阿拉伯/希伯来）、全角、星面字符与转义敏感片段。
const TEXT_POOL: [&str; 12] = [
    "你好，世界",
    "解析器字节跨度自检",
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

/// 损坏行池：截断写入、非 JSON、类型不符——都必须走 record_recoverable 跳过。
const MALFORMED_POOL: [&str; 5] = [
    "{\"timestamp\":\"2026-07-26T00:00:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"id\":\"torn\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"torn wri",
    "{ not json at all",
    "]]]",
    "\"unterminated string",
    "42 trailing garbage }",
];

/// 一条预期产出的权威消息及其渲染行（span 回切的对照物）。
struct ExpectedMessage {
    native_id: String,
    role: String,
    text: String,
    envelope_timestamp: Option<String>,
    line: String,
}

/// 一个生成的 rollout 用例：快照字节 + 全部预期值。
struct GenCase {
    bytes: Vec<u8>,
    session_id: Option<String>,
    expected: Vec<ExpectedMessage>,
    malformed: usize,
    mirrors: usize,
}

fn gen_text(rng: &mut XorShift64Star) -> String {
    let n = 1 + rng.below(3);
    (0..n)
        .map(|_| rng.pick(&TEXT_POOL))
        .collect::<Vec<_>>()
        .join(" ")
}

/// ~256KiB 大字段：多字节图样重复，压大行路径与 UTF-8 span 计算。
fn big_text() -> String {
    let unit = "大字段填充🚀0123456789abcdef ";
    let mut s = String::with_capacity(262_144 + unit.len());
    while s.len() < 262_144 {
        s.push_str(unit);
    }
    s
}

/// 在 `lines` 的随机位置插入一行（既有元素相对顺序不变）。
fn insert_at_random(rng: &mut XorShift64Star, lines: &mut Vec<String>, line: String) {
    let idx = rng.below(lines.len() + 1);
    lines.insert(idx, line);
}

fn build_case(seed: u64, with_big_field: bool) -> GenCase {
    let mut rng = XorShift64Star::new(seed);

    let session_id = rng
        .chance(3, 4)
        .then(|| format!("0198prop-{seed:016x}-sess"));

    // 权威消息 0..=8 条；大字段用例强制至少 1 条，保证大字段真的出现。
    let n_msgs = if with_big_field {
        1 + rng.below(8)
    } else {
        rng.below(9)
    };
    let mut expected: Vec<ExpectedMessage> = Vec::with_capacity(n_msgs);
    for i in 0..n_msgs {
        let role = rng.pick(&ROLES).to_string();
        let id = format!("msg-p{seed:016x}-{i:04}");
        let envelope_timestamp = rng
            .chance(7, 8)
            .then(|| format!("2026-07-26T09:00:{i:02}.000Z"));

        let n_blocks = if with_big_field && i == 0 {
            1 + rng.below(2)
        } else if rng.chance(1, 8) {
            0 // 空 content 数组：parser 仍应产出 text 为空串的消息
        } else {
            1 + rng.below(3)
        };
        let block_type = if role == "assistant" {
            "output_text"
        } else {
            "input_text"
        };
        let mut blocks: Vec<serde_json::Value> = Vec::with_capacity(n_blocks);
        let mut texts: Vec<String> = Vec::new();
        for b in 0..n_blocks {
            if with_big_field && i == 0 && b == 0 {
                let t = big_text();
                blocks.push(json!({"type": block_type, "text": t.clone()}));
                texts.push(t);
            } else if rng.chance(1, 5) {
                // 无 text 字段的 block（如图片输入）——parser 必须跳过不拼接。
                blocks.push(json!({"type": "input_image", "image_url": "synthetic://fixture.png"}));
            } else {
                let t = gen_text(&mut rng);
                blocks.push(json!({"type": block_type, "text": t.clone()}));
                texts.push(t);
            }
        }

        let mut envelope = json!({
            "timestamp": envelope_timestamp.clone(),
            "type": "response_item",
            "payload": {"type": "message", "id": id.clone(), "role": role.clone(), "content": blocks},
        });
        if envelope_timestamp.is_none() {
            // 缺席时间戳以"字段不存在"呈现（而非 null），贴近真实缺字段形态。
            envelope.as_object_mut().unwrap().remove("timestamp");
        }
        expected.push(ExpectedMessage {
            native_id: id,
            role,
            text: texts.join("\n"),
            envelope_timestamp,
            line: envelope.to_string(),
        });
    }

    // 先摆权威行（保持相对顺序），再把镜像与噪声随机穿插进去。
    let mut lines: Vec<String> = expected.iter().map(|m| m.line.clone()).collect();

    // event_msg 镜像：对随机子集（可为空集或全集）各复制一条，位置随机。
    let mut mirrors = 0usize;
    for m in &expected {
        if rng.chance(1, 2) {
            let kind = if m.role == "user" {
                "user_message"
            } else {
                "agent_message"
            };
            let line = json!({
                "timestamp": m
                    .envelope_timestamp
                    .clone()
                    .unwrap_or_else(|| "2026-07-26T09:59:59.000Z".to_string()),
                "type": "event_msg",
                "payload": {"type": kind, "message": m.text.clone()},
            })
            .to_string();
            insert_at_random(&mut rng, &mut lines, line);
            mirrors += 1;
        }
    }

    // 非 message 的 response_item 与 event_msg 噪声：parser 必须静默跳过、不计数。
    for k in 0..rng.below(4) {
        let line = match rng.below(4) {
            0 => json!({
                "timestamp": "2026-07-26T09:58:00.000Z",
                "type": "response_item",
                "payload": {"type": "reasoning", "id": format!("rs-p{seed:016x}-{k}"), "content": null, "summary": [], "encrypted_content": "synthetic-opaque"},
            }),
            1 => json!({
                "timestamp": "2026-07-26T09:58:01.000Z",
                "type": "response_item",
                "payload": {"type": "function_call", "id": format!("fc-p{seed:016x}-{k}"), "name": "synthetic_tool", "arguments": "{\"key\":1}", "call_id": "call-p1"},
            }),
            2 => json!({
                "timestamp": "2026-07-26T09:58:02.000Z",
                "type": "response_item",
                "payload": {"type": "custom_tool_call_output", "call_id": "call-p1", "output": "ok ✅"},
            }),
            _ => json!({
                "timestamp": "2026-07-26T09:58:03.000Z",
                "type": "event_msg",
                "payload": {"type": "token_count", "info": {"total_tokens": 123}},
            }),
        }
        .to_string();
        insert_at_random(&mut rng, &mut lines, line);
    }

    // 损坏行：只允许推进 skipped/diagnostics。
    let mut malformed = 0usize;
    for _ in 0..rng.below(4) {
        let line = rng.pick(&MALFORMED_POOL).to_string();
        insert_at_random(&mut rng, &mut lines, line);
        malformed += 1;
    }

    // 空白行：静默跳过，不进任何计数。
    for _ in 0..rng.below(3) {
        let line = if rng.chance(1, 2) {
            String::new()
        } else {
            "   ".to_string()
        };
        insert_at_random(&mut rng, &mut lines, line);
    }

    // session_meta 固定在首行（真实 rollout 的会话头位置）。
    if let Some(sid) = &session_id {
        lines.insert(
            0,
            json!({
                "timestamp": "2026-07-26T08:59:59.000Z",
                "type": "session_meta",
                "payload": {"session_id": sid, "cwd": "/synthetic/workspace", "originator": "codex_cli_rs", "cli_version": "0.0.0-property"},
            })
            .to_string(),
        );
    }

    // 渲染：每行随机 LF / CRLF；末行 1/4 概率省略行尾。
    let mut bytes = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        bytes.extend_from_slice(line.as_bytes());
        let is_last = i + 1 == lines.len();
        if is_last && rng.chance(1, 4) {
            break;
        }
        bytes.extend_from_slice(if rng.chance(1, 2) { b"\r\n" } else { b"\n" });
    }

    GenCase {
        bytes,
        session_id,
        expected,
        malformed,
        mirrors,
    }
}

/// 对单个种子跑全部六条性质；返回用例供语料覆盖度统计。
fn run_case(seed: u64, with_big_field: bool) -> GenCase {
    let case = build_case(seed, with_big_field);
    let adapter = CodexAdapter::new();

    let mut sink = CollectingSink::default();
    let report = adapter
        .parse(&case.bytes, &mut sink)
        .unwrap_or_else(|e| panic!("seed={seed}: 合法生成的 rollout 不应整体失败: {e}"));

    // 性质 1：镜像不重复计数——committed 只数权威 response_item/message。
    assert_eq!(
        report.committed,
        case.expected.len(),
        "seed={seed} 性质1: committed 应等于权威消息数（mirrors={} malformed={}）",
        case.mirrors,
        case.malformed
    );
    assert_eq!(
        sink.messages.len(),
        case.expected.len(),
        "seed={seed} 性质1: emit 条数应等于权威消息数"
    );

    // 性质 3：seq 从 0 连续（顺序即权威行在文件中的顺序）。
    for (i, got) in sink.messages.iter().enumerate() {
        assert_eq!(got.seq, i as u32, "seed={seed} 性质3: seq 必须从 0 连续");
    }

    // 字段透传 + 性质 2：span 回切到来源封套行。
    for (i, (got, want)) in sink.messages.iter().zip(&case.expected).enumerate() {
        assert_eq!(
            got.native_id, want.native_id,
            "seed={seed} msg[{i}]: native_id 应原样透传"
        );
        assert_eq!(got.role, want.role, "seed={seed} msg[{i}]: role 应原样透传");
        assert_eq!(
            got.text, want.text,
            "seed={seed} msg[{i}]: text 应为带 text 的 block 按序 \\n 拼接"
        );
        assert_eq!(
            got.timestamp, None,
            "seed={seed} msg[{i}]: 外层时间戳属于 occurrence，不进入稳定 Message"
        );
        assert_eq!(
            got.parent_native_id, None,
            "seed={seed} msg[{i}]: codex 线性序列 parent 恒 None"
        );
        assert!(
            !got.is_sidechain,
            "seed={seed} msg[{i}]: codex 无 sidechain"
        );
        let (start, end) = got
            .span
            .unwrap_or_else(|| panic!("seed={seed} msg[{i}]: 必须报告 span"));
        assert_eq!(
            &case.bytes[start as usize..end as usize],
            want.line.as_bytes(),
            "seed={seed} msg[{i}] 性质2: span 必须切回来源封套行（不含行尾）"
        );
    }

    // 性质 5：session_native_id 与生成的 session_meta 完全一致（缺席则 None）。
    assert_eq!(
        report.session_native_id, case.session_id,
        "seed={seed} 性质5: session_native_id 应等于 session_meta 的 session_id"
    );

    // 性质 6：损坏行只进 skipped/diagnostics，且一一对应。
    assert_eq!(
        report.skipped, case.malformed,
        "seed={seed} 性质6: skipped 应恰等于损坏行数"
    );
    assert_eq!(
        report.diagnostics.len(),
        case.malformed,
        "seed={seed} 性质6: 每条损坏行应产生一条诊断"
    );

    // 性质 4：确定性——同一字节再解析一次，事件流与报告完全一致。
    let mut sink2 = CollectingSink::default();
    let report2 = adapter
        .parse(&case.bytes, &mut sink2)
        .unwrap_or_else(|e| panic!("seed={seed} 性质4: 第二次解析不应失败: {e}"));
    assert_eq!(
        sink.messages, sink2.messages,
        "seed={seed} 性质4: 两次解析的事件流必须逐字段一致"
    );
    assert_eq!(
        report.committed, report2.committed,
        "seed={seed} 性质4: committed 两次一致"
    );
    assert_eq!(
        report.skipped, report2.skipped,
        "seed={seed} 性质4: skipped 两次一致"
    );
    assert_eq!(
        report.diagnostics, report2.diagnostics,
        "seed={seed} 性质4: diagnostics 两次一致"
    );
    assert_eq!(
        report.session_native_id, report2.session_native_id,
        "seed={seed} 性质4: session_native_id 两次一致"
    );

    case
}

/// 64 个固定种子的语料；第 0 个迭代附带 ~256KiB 大字段消息。
/// 末尾的覆盖度断言防止生成器退化成"从不生成镜像/损坏行"的空转语料。
#[test]
fn properties_hold_for_fixed_seed_corpus() {
    let mut saw_mirrors = false;
    let mut saw_malformed = false;
    let mut saw_session = false;
    let mut saw_no_session = false;
    let mut saw_messages = false;

    for (i, seed) in fixed_seeds().iter().copied().enumerate() {
        let case = run_case(seed, i == 0);
        saw_mirrors |= case.mirrors > 0;
        saw_malformed |= case.malformed > 0;
        saw_session |= case.session_id.is_some();
        saw_no_session |= case.session_id.is_none();
        saw_messages |= !case.expected.is_empty();
    }

    assert!(
        saw_mirrors && saw_malformed && saw_session && saw_no_session && saw_messages,
        "生成器语料退化：mirrors={saw_mirrors} malformed={saw_malformed} \
         session={saw_session} no_session={saw_no_session} messages={saw_messages}"
    );
}

/// 属性 7（生命周期 append，B5）：在已封口快照末尾追加一条合法
/// `response_item/message` 后，既有消息的 seq/native_id/text/span（含
/// occurrence-local 时间戳规则）必须逐字段不变，新消息追加在末尾——
/// 增量 sync 的"前缀稳定"前提。
#[test]
fn prop_append_keeps_prefix_byte_stable() {
    let adapter = CodexAdapter::new();
    for (i, seed) in fixed_seeds().iter().copied().enumerate() {
        let case = build_case(seed, i == 0);

        let mut extended = case.bytes.clone();
        // 未封口的末行先补行尾，否则追加会与残余字节拼成一行。
        if extended.last().is_some_and(|b| *b != b'\n') {
            extended.push(b'\n');
        }
        let appended = json!({
            "timestamp": "2026-07-26T10:00:00.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": format!("msg-p{seed:016x}-appended"),
                "role": "assistant",
                "content": [{"type": "output_text", "text": "appended lifecycle record"}],
            },
        })
        .to_string();
        let append_start = extended.len() as u64;
        extended.extend_from_slice(appended.as_bytes());
        extended.push(b'\n');

        let mut base_sink = CollectingSink::default();
        let base_report = adapter
            .parse(&case.bytes, &mut base_sink)
            .unwrap_or_else(|e| panic!("seed={seed}: 基准快照解析不应失败: {e}"));
        let mut ext_sink = CollectingSink::default();
        let ext_report = adapter
            .parse(&extended, &mut ext_sink)
            .unwrap_or_else(|e| panic!("seed={seed}: 追加后快照解析不应失败: {e}"));

        assert_eq!(
            ext_sink.messages.len(),
            base_sink.messages.len() + 1,
            "seed={seed}: 追加一条合法记录只新增一条消息"
        );
        assert_eq!(
            ext_sink.messages[..base_sink.messages.len()],
            base_sink.messages[..],
            "seed={seed}: 追加不得移动既有消息的任何字段（含 span）"
        );
        let last = &ext_sink.messages[base_sink.messages.len()];
        assert_eq!(
            last.native_id,
            format!("msg-p{seed:016x}-appended"),
            "seed={seed}: 追加消息 native id 必须原样透传"
        );
        assert_eq!(last.timestamp, None, "seed={seed}: 外层时间戳不进稳定字段");
        assert_eq!(
            last.span,
            Some((append_start, append_start + appended.len() as u64)),
            "seed={seed}: 追加消息 span 必须覆盖追加行（不含行尾）"
        );
        assert_eq!(
            ext_report.committed,
            base_report.committed + 1,
            "seed={seed}: committed 只新增一"
        );
        assert_eq!(
            ext_report.skipped, base_report.skipped,
            "seed={seed}: 追加不得改变既有 skipped 计数"
        );
    }
}
