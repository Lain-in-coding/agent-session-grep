//! QoderAdapter 的确定性 property 套件：固定种子随机 transcript JSONL 与
//! 解析输出之间的不变量（span 回切 / seq 连续 / 计数 / 元数据透传 /
//! type 即角色 / session 身份提取 / 坏行只跳过），外加 golden 源确定性
//! 变异的健壮性不变量（任意变异不 panic / 源只读 / 绝不 partial commit /
//! 同输入同输出）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表。断言信息一律
//! 携带 seed，失败可用该 seed 单独重放；不落盘、不联网。fixture 纯合成，
//! 变异基料为已由 golden.rs BLAKE3 校验钉住的合成 golden 源。

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_qoder::QoderAdapter;
use serde_json::json;

/// crate 内 VARIANT_ID 未导出，测试侧复制并互相印证（probe 报错 variant
/// 会让 registry 挂错 adapter，是 provider_matrix 已钉住的契约）。
const VARIANT_ID: &str = "qoder/transcript-jsonl-v1";

/// golden 源字节（变异测试的基料）。
const GOLDEN: &[u8] = include_bytes!("golden/basic.jsonl");

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
/// JSONL 场景下换行等字符会被 serde 转义，不影响行结构。
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
    r#"{"type":"user","message":{"role":"user","content":"#,
    r#"{"type":"session_meta","session_id":"unterminated"#,
    "not json at all",
    "{]",
    "[1,2,3]",
    r#""just a string""#,
    "42",
];

/// 生成器的 ground truth：独立于 parser 记录"每条有效消息应当以什么形态出现"。
struct ExpectedMessage {
    /// Qoder 的对话角色就是记录的 `type`（user/assistant），message.role 不参与。
    role: String,
    text: String,
    timestamp: Option<String>,
    /// 期望的 span 切片（首条记录含 BOM 前缀，若生成时选用 BOM）。
    span_slice: Vec<u8>,
}

/// 一次迭代生成的完整 transcript 及其应然口径。
struct Generated {
    bytes: Vec<u8>,
    messages: Vec<ExpectedMessage>,
    /// 应计入 skipped 的行数（破损 JSON + 缺 message 体的 user/assistant）。
    skipped: usize,
    /// 应计入 diagnostics 的条数（破损 JSON + 缺体记录 + 多 session 各一条）。
    diagnostics: usize,
    /// 期望的 session_native_id（首个非空 session_id）。
    session_native_id: Option<String>,
    /// 期望的 multi_session 标记（≥2 个不同 session_id）。
    multi_session: bool,
    /// 覆盖度计数：空文本记录（静默跳过）/ 破损行 / 空白行 / 嵌套身份 /
    /// 角色错配（type 与 message.role 不一致）。
    empty_text_records: usize,
    malformed_lines: usize,
    blank_lines: usize,
    nested_identity: usize,
    mismatched_role: usize,
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

/// 与生产 `qoder_content_text` 同规则复刻的提取器（生成器 ground truth
/// 独立对照物）：字符串原样；数组按序拼接 `type:"text"` 块的 `text` 字段
/// （\n 分隔，非 text 块跳过）；其余形态为空串。
fn ground_truth_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(blocks) => {
            let mut buf = String::new();
            for block in blocks {
                if block.get("type").and_then(serde_json::Value::as_str) == Some("text")
                    && let Some(t) = block.get("text").and_then(serde_json::Value::as_str)
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
    }
}

/// 从种子构造随机 transcript：session_meta 头（身份顶层或嵌套）与
/// user/assistant 记录（随机内容形态/时间戳位置/role 错配）同坏行、
/// 非对话记录、空白行交错，行尾 LF/CRLF 混排，首行随机携带 BOM，
/// 末行随机缺行尾符。返回字节与 ground truth。
fn build_transcript(seed: u64, with_large_field: bool) -> Generated {
    let mut rng = XorShift64Star::new(seed);
    let use_bom = rng.chance(25);

    let mut messages: Vec<ExpectedMessage> = Vec::new();
    // 每条消息对应的渲染行索引（span 回填用）。
    let mut message_line: Vec<usize> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();
    let mut skipped = 0usize;
    let mut diagnostics = 0usize;
    let mut session_ids: Vec<String> = Vec::new();
    let mut session_native_id: Option<String> = None;
    let mut empty_text_records = 0usize;
    let mut malformed_lines = 0usize;
    let mut blank_lines = 0usize;
    let mut nested_identity = 0usize;
    let mut mismatched_role = 0usize;

    let line_count = 8 + rng.below(24);
    for i in 0..line_count {
        let force_large_valid = with_large_field && i == 0;
        let roll = if force_large_valid { 0 } else { rng.below(100) };
        if roll < 44 {
            // —— 有效 user/assistant 记录（type 即角色） ——
            let role = ["user", "assistant"][rng.below(2) as usize];
            let (content, expected_text) = if force_large_valid {
                let t = make_text(&mut rng, true);
                (json!(t), t)
            } else {
                match rng.below(100) {
                    0..=54 => {
                        let t = make_text(&mut rng, false);
                        (json!(t.clone()), t)
                    }
                    55..=89 => {
                        let block_count = rng.below(4);
                        let mut blocks = Vec::new();
                        for _ in 0..block_count {
                            if rng.chance(70) {
                                let t = make_text(&mut rng, false);
                                blocks.push(json!({"type": "text", "text": t}));
                            } else {
                                // 非 text 块——不拼接。
                                blocks.push(json!({"type": "tool", "name": "Synthetic"}));
                            }
                        }
                        let text = ground_truth_text(&json!(blocks));
                        (json!(blocks), text)
                    }
                    _ => {
                        // 空文本形态：null / 空数组 / 仅非 text 块——静默跳过。
                        let v = match rng.below(3) {
                            0 => serde_json::Value::Null,
                            1 => json!([]),
                            _ => json!([{"type": "tool", "name": "Synthetic"}]),
                        };
                        (v, String::new())
                    }
                }
            };
            // message.role 与 type 随机错配——钉住"type 是角色"契约。
            let inner_role = if rng.chance(25) {
                mismatched_role += 1;
                if role == "user" { "assistant" } else { "user" }
            } else {
                role
            };
            // 时间戳：message 内 / 记录顶层 / 缺失，随机三选一。
            let mut record = json!({
                "type": role,
                "message": {"role": inner_role, "content": content},
            });
            let timestamp = match rng.below(3) {
                0 => {
                    let ts = format!("2026-01-01T00:{:02}:{:02}Z", rng.below(60), rng.below(60));
                    record["message"]["timestamp"] = json!(ts.clone());
                    Some(ts)
                }
                1 => {
                    let ts = format!("2026-01-01T00:{:02}:{:02}Z", rng.below(60), rng.below(60));
                    record["timestamp"] = json!(ts.clone());
                    Some(ts)
                }
                _ => None,
            };
            let line = serde_json::to_string(&record).expect("render valid chat record");
            if expected_text.trim().is_empty() {
                // 记录合法但文本为空——parser 静默跳过，不 emit、不计数。
                empty_text_records += 1;
                rendered.push(line);
                continue;
            }
            message_line.push(rendered.len());
            messages.push(ExpectedMessage {
                role: role.to_string(),
                text: expected_text,
                timestamp,
                span_slice: Vec::new(), // 渲染阶段按行号回填
            });
            rendered.push(line);
        } else if roll < 52 {
            // —— session_meta 头：身份顶层或嵌套；随机两种 id 制造多 session ——
            let id = [
                format!("prop-sess-a-{seed:016x}"),
                format!("prop-sess-b-{seed:016x}"),
            ][rng.below(2) as usize]
                .clone();
            let mut record = json!({"type": "session_meta"});
            if rng.chance(50) {
                // 顶层身份（真实 Qoder 主形态）。
                record["session_id"] = json!(id.clone());
                record["cwd"] = json!("/synthetic/workspace");
            } else {
                // 嵌套身份（fixture 推导出的宽松匹配形态）。
                nested_identity += 1;
                record["session_meta"] =
                    json!({"session_id": id.clone(), "cwd": "/synthetic/workspace"});
            }
            if rng.chance(50) {
                record["timestamp"] = json!("2026-01-01T00:00:00Z");
            }
            if session_native_id.is_none() {
                session_native_id = Some(id.trim().to_string());
            }
            if !session_ids.iter().any(|s| s == &id) {
                session_ids.push(id.clone());
            }
            rendered.push(serde_json::to_string(&record).expect("render session_meta"));
        } else if roll < 59 {
            // —— progress/tool_use/tool_result：静默略过 ——
            let kind = ["progress", "tool_use", "tool_result"][rng.below(3) as usize];
            let line = serde_json::to_string(&json!({
                "type": kind,
                "message": {"content": "synthetic non-conversational"},
            }))
            .expect("render non-conversational record");
            rendered.push(line);
        } else if roll < 65 {
            // —— user/assistant 缺 message 体：skipped + 诊断 ——
            skipped += 1;
            diagnostics += 1;
            let kind = ["user", "assistant"][rng.below(2) as usize];
            let line =
                serde_json::to_string(&json!({"type": kind})).expect("render no-body record");
            rendered.push(line);
        } else if roll < 73 {
            // —— 坏行：skipped + 诊断 ——
            skipped += 1;
            diagnostics += 1;
            malformed_lines += 1;
            rendered
                .push(MALFORMED_POOL[rng.below(MALFORMED_POOL.len() as u64) as usize].to_string());
        } else if roll < 81 {
            // —— 未知类型记录：静默略过 ——
            let line = serde_json::to_string(&json!({
                "type": "x-future-record",
                "payload": "synthetic non-conversational",
            }))
            .expect("render unknown type record");
            rendered.push(line);
        } else if roll < 89 {
            // —— 无身份 session_meta（无 session_id）：不贡献身份，静默略过 ——
            let line = serde_json::to_string(&json!({
                "type": "session_meta",
                "cwd": "/synthetic/workspace",
            }))
            .expect("render identity-less session_meta");
            rendered.push(line);
        } else {
            // —— 空白行：静默略过，但仍占字节偏移 ——
            blank_lines += 1;
            rendered.push(if rng.chance(50) {
                String::new()
            } else {
                "   ".to_string()
            });
        }
    }

    // 前提是"存在有效记录"；极端种子下若一条未生成则强制补一条。
    if messages.is_empty() {
        let line = serde_json::to_string(&json!({
            "type": "user",
            "message": {"role": "user", "content": "forced valid record"},
        }))
        .expect("render forced record");
        message_line.push(rendered.len());
        messages.push(ExpectedMessage {
            role: "user".to_string(),
            text: "forced valid record".to_string(),
            timestamp: None,
            span_slice: Vec::new(),
        });
        rendered.push(line);
    }

    // 渲染字节：逐行随机 LF / CRLF；首行随机 BOM 前缀；末行 30% 概率不带行尾符。
    // span 坐标系（BoundedSourceLine）：首条记录的 end 包含 BOM、排除行尾符。
    let mut bytes = Vec::new();
    let total = rendered.len();
    for (idx, line) in rendered.iter().enumerate() {
        if idx == 0 && use_bom {
            bytes.extend_from_slice(b"\xEF\xBB\xBF");
        }
        bytes.extend_from_slice(line.as_bytes());
        if idx + 1 == total && rng.chance(30) {
            break;
        }
        bytes.extend_from_slice(if rng.chance(50) { b"\r\n" } else { b"\n" });
    }

    // 回填 span 切片：每条消息的行负载（首行含 BOM、不含行尾符）。
    for (m_idx, &line_idx) in message_line.iter().enumerate() {
        let mut payload = Vec::new();
        if line_idx == 0 && use_bom {
            payload.extend_from_slice(b"\xEF\xBB\xBF");
        }
        payload.extend_from_slice(rendered[line_idx].as_bytes());
        messages[m_idx].span_slice = payload;
    }

    // 多 session 诊断：≥2 个不同 id → 多一条诊断 + multi_session 标记。
    let multi_session = session_ids.len() > 1;
    if multi_session {
        diagnostics += 1;
    }

    Generated {
        bytes,
        messages,
        skipped,
        diagnostics,
        session_native_id,
        multi_session,
        empty_text_records,
        malformed_lines,
        blank_lines,
        nested_identity,
        mismatched_role,
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

/// 解析生成的 transcript；含有效记录时 parse 绝不允许整体失败。
fn parse_bytes(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = QoderAdapter::new()
        .parse(bytes, &mut sink)
        .unwrap_or_else(|e| panic!("seed={seed}: parse 在存在有效记录时整体失败：{e}"));
    (report, sink.messages)
}

// ---------------------------------------------------------------------------
// 确定性变异工具（golden 源变异测试用）
// ---------------------------------------------------------------------------

/// 变异字节负载池：JSON 标点 / 换行 / 高位字节 / NUL / UTF-8 片段。
const MUTATION_FRAGMENTS: &[&[u8]] = &[
    b"\"",
    b"{",
    b"}",
    b"[",
    b"]",
    b":",
    b",",
    b"\\",
    b"\n",
    b"\r\n",
    b"\t",
    b"\x00",
    b"\x80",
    b"\xFF",
    "会".as_bytes(),
    b"{\"type\":\"user\"",
];

fn random_payload(rng: &mut XorShift64Star, max_len: usize) -> Vec<u8> {
    let len = 1 + rng.below(max_len as u64) as usize;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        if rng.chance(50) {
            out.push(rng.below(256) as u8);
        } else {
            let frag = MUTATION_FRAGMENTS[rng.below(MUTATION_FRAGMENTS.len() as u64) as usize];
            out.extend_from_slice(frag);
        }
    }
    out
}

/// 对字节施加 1..=3 个确定性变异：随机截断 / 插入 / 删除 / 翻转字节 /
/// 拆行 / 乱序行。
fn mutate(bytes: &mut Vec<u8>, rng: &mut XorShift64Star) {
    let ops = 1 + rng.below(3);
    for _ in 0..ops {
        match rng.below(6) {
            0 => {
                // 随机截断（可为 0，产生空输入）。
                let n = rng.below(bytes.len() as u64 + 1) as usize;
                bytes.truncate(n);
            }
            1 => {
                // 随机位置插入随机字节。
                let pos = rng.below(bytes.len() as u64 + 1) as usize;
                let payload = random_payload(rng, 48);
                bytes.splice(pos..pos, payload);
            }
            2 if !bytes.is_empty() => {
                // 删除随机字节区间。
                let a = rng.below(bytes.len() as u64) as usize;
                let max_b = (bytes.len() - a).max(1) as u64;
                let b = 1 + rng.below(max_b) as usize;
                bytes.drain(a..a + b);
            }
            3 if !bytes.is_empty() => {
                // 翻转 1..=8 个随机字节（含高位字节 → 大概率破坏 UTF-8/JSON）。
                let flips = 1 + rng.below(8);
                for _ in 0..flips {
                    let i = rng.below(bytes.len() as u64) as usize;
                    bytes[i] = rng.below(256) as u8;
                }
            }
            4 if !bytes.is_empty() => {
                // 拆行：随机位置插入 \n。
                let pos = rng.below(bytes.len() as u64) as usize;
                bytes.insert(pos, b'\n');
            }
            _ if bytes.len() >= 2 => {
                // 乱序行：按行切分（含行尾符），交换两段，再拼回。
                let mut units: Vec<Vec<u8>> = Vec::new();
                let mut cur = Vec::new();
                for &b in bytes.iter() {
                    cur.push(b);
                    if b == b'\n' {
                        units.push(std::mem::take(&mut cur));
                    }
                }
                if !cur.is_empty() {
                    units.push(cur);
                }
                if units.len() >= 2 {
                    for _ in 0..2 {
                        let a = rng.below(units.len() as u64) as usize;
                        let b = rng.below(units.len() as u64) as usize;
                        if a != b {
                            units.swap(a, b);
                        }
                    }
                }
                *bytes = units.concat();
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// 属性 1：probe 对任意字节永不 panic；Ok 时 variant/置信度/证据合理，
// 且 probe 确定、源只读。
// ---------------------------------------------------------------------------

fn make_probe_blob(rng: &mut XorShift64Star) -> Vec<u8> {
    let len = rng.below(1024) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let fragments: &[&[u8]] = &[
        br#"{"type":"user","message":{"role":"user","content":"hi"}}"#,
        br#"{"type":"session_meta","session_id":"s-1","cwd":"/p"}"#,
        br#"{"type":"session_meta","payload":{"session_id":"s-1"}}"#,
        b"not json at all",
        b"\n\r\n",
        "会话🚀".as_bytes(),
        b"\"{}",
        GOLDEN,
    ];
    while out.len() < len {
        if rng.chance(60) {
            out.push(rng.below(256) as u8);
        } else {
            out.extend_from_slice(fragments[rng.below(fragments.len() as u64) as usize]);
        }
    }
    out.truncate(len);
    out
}

#[test]
fn prop_probe_arbitrary_bytes_never_panics() {
    for (idx, &seed) in SEEDS.iter().enumerate() {
        let mut rng = XorShift64Star::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut blob = make_probe_blob(&mut rng);
        if idx == 0 {
            // 额外覆盖：对 golden 源施加一次变异后 probe。
            blob = GOLDEN.to_vec();
            mutate(&mut blob, &mut rng);
        }
        let before = blob.clone();
        let adapter = QoderAdapter::new();
        let r1 = adapter.probe(&blob);
        let r2 = adapter.probe(&blob);
        assert_eq!(blob, before, "seed={seed}: probe 不得改写源字节");
        assert_eq!(r1, r2, "seed={seed}: probe 必须确定");
        if let Ok(result) = r1 {
            assert_eq!(
                result.variant_id, VARIANT_ID,
                "seed={seed}: probe 不得报告其它 variant"
            );
            assert!(
                !matches!(result.confidence, Confidence::Ambiguous),
                "seed={seed}: Ok 的 probe 不得携带 Ambiguous 置信度"
            );
            assert!(
                !result.matched_evidence.is_empty(),
                "seed={seed}: Ok 的 probe 必须携带匹配证据"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 属性 2：golden 源确定性变异——parse 永不 panic、源只读、绝不 partial
// commit、Ok 时消息字段合法、同输入同输出。
// ---------------------------------------------------------------------------

#[test]
fn prop_golden_mutations_never_panic_nor_partial_commit() {
    for &seed in &SEEDS {
        let mut rng = XorShift64Star::new(seed ^ 0x243f_6a88_85a3_08d3);
        let mut bytes = GOLDEN.to_vec();
        mutate(&mut bytes, &mut rng);
        let before = bytes.clone();
        let adapter = QoderAdapter::new();

        let mut sink = CollectingSink::default();
        let result = adapter.parse(&bytes, &mut sink);
        assert_eq!(
            &bytes, &before,
            "seed={seed}: parse 不得改写源字节（RFC-0002 §7）"
        );

        match &result {
            Ok(report) => {
                assert_eq!(
                    report.committed,
                    sink.messages.len(),
                    "seed={seed}: committed 必须等于实际 emit 数——绝不 partial commit"
                );
                for (i, m) in sink.messages.iter().enumerate() {
                    assert_eq!(m.seq, i as u32, "seed={seed}: seq 必须从 0 连续");
                    assert!(
                        matches!(m.role.as_str(), "user" | "assistant"),
                        "seed={seed} msg[{i}]: 角色必须收敛到 user/assistant"
                    );
                    assert!(
                        !m.text.trim().is_empty(),
                        "seed={seed} msg[{i}]: 已 emit 的消息文本不得为空"
                    );
                    assert!(
                        m.native_id.is_empty(),
                        "seed={seed} msg[{i}]: qoder 不提供 native id，绝不编造"
                    );
                    let (s, e) = m
                        .span
                        .unwrap_or_else(|| panic!("seed={seed} msg[{i}]: 必须携带 span"));
                    assert!(
                        s <= e && e <= bytes.len() as u64,
                        "seed={seed} msg[{i}]: span ({s},{e}) 必须在源字节界内"
                    );
                    let slice = &bytes[s as usize..e as usize];
                    assert!(
                        std::str::from_utf8(slice).is_ok(),
                        "seed={seed} msg[{i}]: span 切片必须是有效 UTF-8（它解析自该行）"
                    );
                }
            }
            Err(_) => {
                // 整体失败是契约允许的可恢复路径（上层回滚 staging）。
            }
        }

        // 确定性：同输入同输出（含错误路径）。
        let mut sink2 = CollectingSink::default();
        let again = adapter.parse(&bytes, &mut sink2);
        match (&result, &again) {
            (Ok(r1), Ok(r2)) => {
                assert_eq!(r1, r2, "seed={seed}: 两次解析的报告必须一致");
                assert_eq!(
                    sink.messages, sink2.messages,
                    "seed={seed}: 两次解析的事件流必须一致"
                );
            }
            (Err(e1), Err(e2)) => {
                assert_eq!(e1, e2, "seed={seed}: 错误路径必须同样确定");
            }
            _ => panic!("seed={seed}: 同一输入的成败结果不得漂移"),
        }
    }
}

// ---------------------------------------------------------------------------
// 属性 3：生成 transcript 与 ground truth 逐字段一致（span 回切 / seq 连续 /
// 计数 / 元数据 / type 即角色 / session 身份 / 坏行只跳过 / 确定性）。
// ---------------------------------------------------------------------------

#[test]
fn prop_generated_transcripts_match_ground_truth() {
    let mut saw_empty_text = false;
    let mut saw_malformed = false;
    let mut saw_blank = false;
    let mut saw_multi_session = false;
    let mut saw_bom = false;
    let mut saw_nested_identity = false;
    let mut saw_mismatched_role = false;

    for (idx, &seed) in SEEDS.iter().enumerate() {
        let case = build_transcript(seed, idx == 0);
        saw_empty_text |= case.empty_text_records > 0;
        saw_malformed |= case.malformed_lines > 0;
        saw_blank |= case.blank_lines > 0;
        saw_multi_session |= case.multi_session;
        saw_bom |= case.bytes.starts_with(b"\xEF\xBB\xBF");
        saw_nested_identity |= case.nested_identity > 0;
        saw_mismatched_role |= case.mismatched_role > 0;

        let (report, captured) = parse_bytes(seed, &case.bytes);

        assert_eq!(
            captured.len(),
            case.messages.len(),
            "seed={seed}: 消息数必须等于 ground truth"
        );
        assert_eq!(
            report.committed,
            case.messages.len(),
            "seed={seed}: committed 必须等于 ground truth 有效消息数"
        );

        for (i, (got, want)) in captured.iter().zip(&case.messages).enumerate() {
            assert_eq!(got.seq, i as u32, "seed={seed}: seq 必须从 0 连续递增");
            assert_eq!(
                got.native_id, "",
                "seed={seed} msg[{i}]: native_id 必须为空（绝不编造）"
            );
            assert_eq!(
                got.parent_native_id, None,
                "seed={seed} msg[{i}]: qoder 无 threading 边"
            );
            assert_eq!(
                got.role, want.role,
                "seed={seed} msg[{i}]: role 必须等于记录 type（与 message.role 无关）"
            );
            assert_eq!(
                got.text, want.text,
                "seed={seed} msg[{i}]: 文本必须原样抽取"
            );
            assert_eq!(
                got.timestamp, want.timestamp,
                "seed={seed} msg[{i}]: timestamp 必须原样透传（message 内优先）"
            );
            assert!(
                !got.is_sidechain,
                "seed={seed} msg[{i}]: qoder 无 sidechain"
            );
            let (start, end) = got
                .span
                .unwrap_or_else(|| panic!("seed={seed} msg[{i}]: 必须携带 span"));
            let slice = &case.bytes[start as usize..end as usize];
            assert_eq!(
                slice,
                want.span_slice.as_slice(),
                "seed={seed} msg[{i}]: span 切片必须逐字节等于源记录行（含首行 BOM、去行尾）"
            );
        }

        assert_eq!(
            report.skipped, case.skipped,
            "seed={seed}: skipped 必须恰等于注入的坏行 + 缺体记录数"
        );
        assert_eq!(
            report.diagnostics.len(),
            case.diagnostics,
            "seed={seed}: 诊断数必须恰等于破损 JSON + 缺体记录 + 多 session 各一条"
        );
        assert_eq!(
            report.session_native_id, case.session_native_id,
            "seed={seed}: session_native_id 必须等于首个非空 session_id（顶层或嵌套）"
        );
        assert_eq!(
            report.session_observation.multi_session, case.multi_session,
            "seed={seed}: multi_session 标记必须与注入的 session id 数一致"
        );

        // 确定性：同一字节再解析一次完全一致。
        let (report2, captured2) = parse_bytes(seed, &case.bytes);
        assert_eq!(report, report2, "seed={seed}: 两次解析的报告必须一致");
        assert_eq!(captured, captured2, "seed={seed}: 两次解析的事件流必须一致");
    }

    assert!(
        saw_empty_text
            && saw_malformed
            && saw_blank
            && saw_multi_session
            && saw_bom
            && saw_nested_identity
            && saw_mismatched_role,
        "生成器语料退化：empty_text={saw_empty_text} malformed={saw_malformed} \
         blank={saw_blank} multi_session={saw_multi_session} bom={saw_bom} \
         nested_identity={saw_nested_identity} mismatched_role={saw_mismatched_role}"
    );
}
