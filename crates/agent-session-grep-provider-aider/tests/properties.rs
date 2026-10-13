//! AiderAdapter 的确定性 property 套件：固定种子随机
//! `.aider.chat.history.md`（Markdown 行前缀状态机）与解析输出之间的
//! 不变量（块聚合 / seq 连续 / 计数 / 近似 span 语义 / session 头提取 /
//! 空块只跳过），外加 golden 源确定性变异的健壮性不变量（任意变异不
//! panic / 源只读 / 绝不 partial commit / 同输入同输出）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表。断言信息一律
//! 携带 seed，失败可用该 seed 单独重放；不落盘、不联网。fixture 纯合成，
//! 变异基料为已由 golden.rs BLAKE3 校验钉住的合成 golden 源。
//!
//! aider 的 span 是"块起点 + 未修剪文本字节长"的派生近似（crate 模块文档与
//! manifest known_limitations 已声明），因此这里的 span 断言是"界内 + 长度
//! 恒等式"，而不是 JSONL provider 的逐字节回切。

use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_aider::AiderAdapter;

/// crate 内 VARIANT_ID 未导出，测试侧复制并互相印证（probe 报错 variant
/// 会让 registry 挂错 adapter，是 provider_matrix 已钉住的契约）。
const VARIANT_ID: &str = "aider/chat-history-md-v1";

/// golden 源字节（变异测试的基料）。
const GOLDEN: &[u8] = include_bytes!("golden/basic.md");

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

/// 行文本池：CJK / 日韩 / emoji / RTL（阿拉伯文、带附加符希伯来文）/
/// 4 字节数学字母 / 引号反斜杠 / 零宽字符 / 首尾空白。
/// 与 JSONL provider 不同：**不得含内嵌换行**——aider 是行级 Markdown，
/// 池内换行会破坏行结构；空串也不进池（空白行单独生成）。
const TEXT_POOL: &[&str] = &[
    "plain ascii text",
    "会话历史检索引擎",
    "こんにちは、世界",
    "안녕하세요",
    "🚀🌏🧪✨",
    "مرحبا بالعالم",
    "שָׁלוֹם עוֹלָם",
    "𝕌𝕟𝕚𝕔𝕠𝕕𝕖 mathematical",
    "quote\" and back\\slash",
    "zero\u{200B}width",
    "  leading and trailing spaces  ",
    "tab\there",
];

/// 渲染行（含字节起点）：生成器输出、oracle 输入。
struct SourceLine {
    text: String,
    /// 该行在最终字节流中的起点（首行含 BOM 时起点为 0，BOM 计入首行）。
    start: u64,
}

/// 生成器的 ground truth：独立于 parser 记录"每条有效消息应当以什么形态出现"。
struct ExpectedMessage {
    role: String,
    /// flush 时 emit 的文本（未修剪文本的 trim 形态）。
    text: String,
    /// 派生近似 span：(块起点, 块起点 + 未修剪文本字节长)。
    span: (u64, u64),
}

/// 一次迭代生成的完整 transcript 及其应然口径。
struct Generated {
    bytes: Vec<u8>,
    messages: Vec<ExpectedMessage>,
    /// 期望的 session_native_id（首个 `# aider chat started at` 头的时间戳）。
    session_native_id: Option<String>,
    /// 覆盖度计数：各类行与状态机路径。
    user_prompts: usize,
    assistant_lines: usize,
    blockquotes: usize,
    headers: usize,
    blank_lines: usize,
    empty_blocks: usize,
    blockquote_into_user_block: usize,
}

/// 取一段随机行文本；`large` 时拼出 ~256 KiB 多字节大字段。
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

/// 按文档契约独立实现的行前缀状态机 oracle：消费 SourceLine 序列，产出
/// 期望消息与 session id。实现组织与 adapter 不同（adapter 是流式 flush
/// 闭包，这里是先收集块再派生），但规则逐条对照模块文档。
///
/// 两个行标记在此**独立重写**（不从被测 crate 导入）：oracle 的价值就在于它是
/// 契约的第二份实现，共享匹配器会让它退化成实现的复述。
fn oracle_user_prompt_body(line: &str) -> Option<&str> {
    match line {
        "####" => Some(""),
        _ => line.strip_prefix("#### "),
    }
}

fn oracle_tool_output_body(line: &str) -> Option<&str> {
    match line {
        ">" => Some(""),
        _ => line.strip_prefix("> "),
    }
}

fn oracle(lines: &[SourceLine], use_bom: bool) -> (Vec<ExpectedMessage>, Option<String>) {
    let mut messages: Vec<ExpectedMessage> = Vec::new();
    let mut session_native_id: Option<String> = None;

    let mut current_role: Option<String> = None;
    let mut current_text = String::new();
    let mut current_start: u64 = 0;

    let flush = |role: &str, text: &mut String, start: u64, messages: &mut Vec<ExpectedMessage>| {
        if text.trim().is_empty() {
            text.clear();
            return;
        }
        let end = start + text.len() as u64;
        messages.push(ExpectedMessage {
            role: role.to_string(),
            text: text.trim().to_string(),
            span: (start, end),
        });
        text.clear();
    };

    for (idx, line) in lines.iter().enumerate() {
        let parse_line = if idx == 0 && use_bom {
            line.text.strip_prefix('\u{feff}').unwrap_or(&line.text)
        } else {
            line.text.as_str()
        };
        let trimmed = parse_line.trim_start();

        if trimmed.starts_with("# aider chat started at ") {
            if let Some(role) = current_role.take() {
                flush(&role, &mut current_text, current_start, &mut messages);
            }
            if session_native_id.is_none() {
                session_native_id = trimmed
                    .strip_prefix("# aider chat started at ")
                    .map(|ts| ts.trim().to_string());
            }
            continue;
        }

        if let Some(rest) = oracle_user_prompt_body(trimmed) {
            // 连续的 `#### ` 行属于同一条提示（aider 的多行输入形态）：留在
            // user 频道就追加，只有频道切换时才 flush。裸 `####` 是空输入标记，
            // 属 user 频道且不贡献正文。
            if current_role.as_deref() == Some("user") {
                if !current_text.is_empty() {
                    current_text.push('\n');
                }
                current_text.push_str(rest);
                continue;
            }
            if let Some(role) = current_role.take() {
                flush(&role, &mut current_text, current_start, &mut messages);
            }
            current_role = Some("user".to_string());
            current_text = rest.to_string();
            current_start = line.start;
        } else if let Some(rest) = oracle_tool_output_body(trimmed) {
            // 工具输出频道：aider 自己的输出永远不是用户的话，故它必须结束
            // user 块（上游 agentsview 的频道切换语义），再按已声明的限制
            // 折叠进 assistant 正文。
            if current_role.as_deref() == Some("user") {
                flush("user", &mut current_text, current_start, &mut messages);
                current_role = None;
            }
            if current_role.is_none() {
                current_role = Some("assistant".to_string());
                current_start = line.start;
            }
            if !current_text.is_empty() {
                current_text.push('\n');
            }
            current_text.push_str(rest);
        } else if !parse_line.trim().is_empty() {
            if current_role.is_none() || current_role.as_deref() == Some("user") {
                if current_role.is_some() {
                    let role = current_role.take().unwrap();
                    flush(&role, &mut current_text, current_start, &mut messages);
                }
                current_role = Some("assistant".to_string());
                current_start = line.start;
            }
            if !current_text.is_empty() {
                current_text.push('\n');
            }
            current_text.push_str(parse_line.trim());
        }
        // 空白行：完全忽略（不 flush、不加分隔符）。
    }

    if let Some(role) = current_role {
        flush(&role, &mut current_text, current_start, &mut messages);
    }

    (messages, session_native_id)
}

/// 从种子构造随机 Markdown：chat 头、user 提示（h4）、assistant 正文行、
/// blockquote 工具输出、空白行随机交错；行尾 LF/CRLF 混排，首行随机携带
/// BOM，末行随机缺行尾符。返回字节与 ground truth。
fn build_transcript(seed: u64, with_large_field: bool) -> Generated {
    let mut rng = XorShift64Star::new(seed);
    let use_bom = rng.chance(25);

    let mut lines: Vec<SourceLine> = Vec::new();
    let mut user_prompts = 0usize;
    let mut assistant_lines = 0usize;
    let mut blockquotes = 0usize;
    let mut headers = 0usize;
    let mut blank_lines = 0usize;

    let line_count = 10 + rng.below(26);
    for i in 0..line_count {
        let force_large = with_large_field && i == 0;
        let roll = if force_large { 40 } else { rng.below(100) };
        if roll < 30 {
            // —— user 提示（h4）——
            user_prompts += 1;
            // 10% 空提示 → 空块被静默丢弃；其中一半写成 aider 的**裸** `####`
            // （空输入形态，上游 agentsview 以 `line == "####"` 单独匹配），
            // 另一半写成带空格的 `"#### "`。
            let text = if rng.chance(10) {
                if rng.chance(50) {
                    "####".to_string()
                } else {
                    "#### ".to_string()
                }
            } else {
                format!("#### {}", make_text(&mut rng, false))
            };
            lines.push(SourceLine {
                text,
                start: 0, // 渲染阶段回填
            });
        } else if roll < 65 || force_large {
            // —— assistant 正文行 ——
            assistant_lines += 1;
            let content = make_text(&mut rng, force_large);
            lines.push(SourceLine {
                text: content,
                start: 0,
            });
        } else if roll < 80 {
            // —— blockquote 工具输出 ——
            blockquotes += 1;
            // 空输出同上：一半写成裸 `>`（上游以 `line == ">"` 单独匹配）。
            let text = if rng.chance(10) {
                if rng.chance(50) {
                    ">".to_string()
                } else {
                    "> ".to_string()
                }
            } else {
                format!("> {}", make_text(&mut rng, false))
            };
            lines.push(SourceLine { text, start: 0 });
        } else if roll < 90 {
            // —— chat 头（多 run 场景）——
            headers += 1;
            let ts = format!(
                "2026-01-01 {:02}:{:02}:{:02}",
                rng.below(24),
                rng.below(60),
                rng.below(60)
            );
            lines.push(SourceLine {
                text: format!("# aider chat started at {ts}"),
                start: 0,
            });
        } else if roll < 96 {
            // —— 非 h4 的其它 Markdown 标题/普通行：全走 assistant 分支 ——
            assistant_lines += 1;
            let kind = ["### level three", "##### five hashes", "## sub heading"];
            let extra = make_text(&mut rng, false);
            lines.push(SourceLine {
                text: format!("{} {}", kind[rng.below(3) as usize], extra),
                start: 0,
            });
        } else {
            // —— 空白行 ——
            blank_lines += 1;
            lines.push(SourceLine {
                text: if rng.chance(50) {
                    String::new()
                } else {
                    "   ".to_string()
                },
                start: 0,
            });
        }
    }

    // 前提是"存在有效消息"；极端种子下若全为空块/无行则强制补一条 user 提示。
    if lines.is_empty() {
        lines.push(SourceLine {
            text: "#### forced valid prompt".to_string(),
            start: 0,
        });
        user_prompts += 1;
    }

    // 渲染字节并回填行起点：逐行随机 LF / CRLF；首行随机 BOM；末行 30% 缺行尾符。
    let mut bytes = Vec::new();
    let total = lines.len();
    let mut offset: u64 = 0;
    for (idx, line) in lines.iter_mut().enumerate() {
        line.start = offset;
        if idx == 0 && use_bom {
            bytes.extend_from_slice(b"\xEF\xBB\xBF");
        }
        bytes.extend_from_slice(line.text.as_bytes());
        if idx + 1 == total && rng.chance(30) {
            break;
        }
        bytes.extend_from_slice(if rng.chance(50) { b"\r\n" } else { b"\n" });
        offset = bytes.len() as u64;
    }

    // oracle 派生 ground truth。
    let (messages, session_native_id) = oracle(&lines, use_bom);

    // 覆盖度：blockquote 直接跟在 user 块后（该行必须结束 user 块的路径）。
    // 由 oracle 之外单独统计：渲染序列中提示行后紧邻工具输出行。
    let mut blockquote_into_user_block = 0usize;
    let mut prev_was_prompt = false;
    for line in &lines {
        let trimmed = line.text.trim_start();
        let is_prompt = trimmed == "####" || trimmed.starts_with("#### ");
        let is_quote = trimmed == ">" || trimmed.starts_with("> ");
        if is_quote && prev_was_prompt {
            blockquote_into_user_block += 1;
        }
        prev_was_prompt = is_prompt;
    }

    // 空块计数：生成的空提示与空 blockquote（其块 flush 时被静默丢弃）。
    let empty_blocks = lines
        .iter()
        .filter(|l| {
            let t = l.text.trim_start();
            t == "####"
                || t == ">"
                || (t.starts_with("#### ")
                    && t.strip_prefix("#### ").unwrap_or("").trim().is_empty())
                || (t.starts_with("> ") && t.strip_prefix("> ").unwrap_or("").trim().is_empty())
        })
        .count();

    Generated {
        bytes,
        messages,
        session_native_id,
        user_prompts,
        assistant_lines,
        blockquotes,
        headers,
        blank_lines,
        empty_blocks,
        blockquote_into_user_block,
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

/// 解析生成的 transcript；含有效消息时 parse 绝不允许整体失败。
fn parse_bytes(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = AiderAdapter::new()
        .parse(bytes, &mut sink)
        .unwrap_or_else(|e| panic!("seed={seed}: parse 在存在有效消息时整体失败：{e}"));
    (report, sink.messages)
}

// ---------------------------------------------------------------------------
// 确定性变异工具（golden 源变异测试用）
// ---------------------------------------------------------------------------

/// 变异字节负载池：Markdown 前缀 / 换行 / 高位字节 / NUL / UTF-8 片段。
const MUTATION_FRAGMENTS: &[&[u8]] = &[
    b"# aider chat started at ",
    b"#### ",
    b"> ",
    b"\n",
    b"\r\n",
    b"\t",
    b"\x00",
    b"\x80",
    b"\xFF",
    "会".as_bytes(),
    b"plain text",
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
                // 翻转 1..=8 个随机字节（含高位字节 → 大概率破坏 UTF-8）。
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
        b"# aider chat started at 2026-01-01 12:00:00\n\n#### Hello?\n",
        b"#### a prompt without a header\n",
        b"# Some random markdown\n\nHello world\n",
        b"not markdown at all",
        b"\n\r\n",
        "会话🚀".as_bytes(),
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
        let adapter = AiderAdapter::new();
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
        let adapter = AiderAdapter::new();

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
                        "seed={seed} msg[{i}]: aider 不提供 native id，绝不编造"
                    );
                    let (s, e) = m
                        .span
                        .unwrap_or_else(|| panic!("seed={seed} msg[{i}]: 必须携带 span"));
                    assert!(
                        s <= e && e <= bytes.len() as u64,
                        "seed={seed} msg[{i}]: span ({s},{e}) 必须在源字节界内"
                    );
                    assert!(
                        (e - s) as usize >= m.text.len(),
                        "seed={seed} msg[{i}]: span 长度（未修剪）不得短于 emit 文本（已修剪）"
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
// 属性 3：生成 Markdown 与 oracle ground truth 逐字段一致（块聚合 / seq 连续 /
// 计数 / 近似 span 恒等式 / session 头提取 / 空块只跳过 / 确定性）。
// ---------------------------------------------------------------------------

#[test]
fn prop_generated_transcripts_match_ground_truth() {
    let mut saw_prompts = false;
    let mut saw_assistant = false;
    let mut saw_quotes = false;
    let mut saw_headers = false;
    let mut saw_blank = false;
    let mut saw_empty_blocks = false;
    let mut saw_quote_into_user = false;
    let mut saw_bom = false;

    for (idx, &seed) in SEEDS.iter().enumerate() {
        let case = build_transcript(seed, idx == 0);
        saw_prompts |= case.user_prompts > 0;
        saw_assistant |= case.assistant_lines > 0;
        saw_quotes |= case.blockquotes > 0;
        saw_headers |= case.headers > 0;
        saw_blank |= case.blank_lines > 0;
        saw_empty_blocks |= case.empty_blocks > 0;
        saw_quote_into_user |= case.blockquote_into_user_block > 0;
        saw_bom |= case.bytes.starts_with(b"\xEF\xBB\xBF");

        let (report, captured) = parse_bytes(seed, &case.bytes);

        assert_eq!(
            captured.len(),
            case.messages.len(),
            "seed={seed}: 消息数必须等于 oracle ground truth"
        );
        assert_eq!(
            report.committed,
            case.messages.len(),
            "seed={seed}: committed 必须等于 oracle 有效消息数"
        );

        for (i, (got, want)) in captured.iter().zip(&case.messages).enumerate() {
            assert_eq!(got.seq, i as u32, "seed={seed}: seq 必须从 0 连续递增");
            assert_eq!(
                got.native_id, "",
                "seed={seed} msg[{i}]: native_id 必须为空（绝不编造）"
            );
            assert_eq!(
                got.parent_native_id, None,
                "seed={seed} msg[{i}]: aider 无 threading 边"
            );
            assert_eq!(
                got.role, want.role,
                "seed={seed} msg[{i}]: 角色必须等于 oracle 派生角色"
            );
            assert_eq!(
                got.text, want.text,
                "seed={seed} msg[{i}]: 文本必须等于 oracle 派生的 trim 形态"
            );
            assert_eq!(
                got.timestamp, None,
                "seed={seed} msg[{i}]: aider 不提取时间戳"
            );
            assert!(
                !got.is_sidechain,
                "seed={seed} msg[{i}]: aider 无 sidechain"
            );
            let (start, end) = got
                .span
                .unwrap_or_else(|| panic!("seed={seed} msg[{i}]: 必须携带 span"));
            assert_eq!(
                (start, end),
                want.span,
                "seed={seed} msg[{i}]: 派生近似 span 必须等于 oracle（块起点 + 未修剪长度）"
            );
            assert!(
                start <= end && end <= case.bytes.len() as u64,
                "seed={seed} msg[{i}]: span 必须在源字节界内"
            );
            assert_eq!(
                end - start,
                (case.bytes[start as usize..end as usize]).len() as u64,
                "seed={seed} msg[{i}]: span 区间必须可切回源字节"
            );
        }

        assert_eq!(
            report.skipped, 0,
            "seed={seed}: aider 行级解析没有可恢复跳过路径，skipped 必须为 0"
        );
        assert_eq!(
            report.session_native_id, case.session_native_id,
            "seed={seed}: session_native_id 必须等于首个 chat 头的时间戳"
        );

        // 确定性：同一字节再解析一次完全一致。
        let (report2, captured2) = parse_bytes(seed, &case.bytes);
        assert_eq!(report, report2, "seed={seed}: 两次解析的报告必须一致");
        assert_eq!(captured, captured2, "seed={seed}: 两次解析的事件流必须一致");
    }

    assert!(
        saw_prompts && saw_assistant && saw_quotes && saw_headers && saw_blank,
        "生成器语料退化：prompts={saw_prompts} assistant={saw_assistant} \
         quotes={saw_quotes} headers={saw_headers} blank={saw_blank}"
    );
    assert!(
        saw_empty_blocks && saw_quote_into_user && saw_bom,
        "状态机路径语料退化：empty_blocks={saw_empty_blocks} \
         quote_into_user={saw_quote_into_user} bom={saw_bom}"
    );
}
