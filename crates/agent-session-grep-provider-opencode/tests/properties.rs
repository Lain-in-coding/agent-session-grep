//! OpenCode adapter（`opencode/sqlite-v1`）的确定性 property 套件。
//!
//! OpenCode 源是 SQLite（session/message/part 三表），与 JSONL 系 provider
//! 的结构不同：无字节 span、消息按 `time_created` 全局排序、角色与正文来自
//! `data` 列的 JSON。生成器在内存里用 rusqlite 建随机库（多会话 / 混合角色 /
//! 无正文 / 坏 JSON data / tool part / 空白正文），经 VACUUM INTO 落成字节
//! 再喂给 adapter，逐条验证：
//!
//! 1. span 恒 None（SQLite 无文件内字节坐标）；
//! 2. seq 从 0 连续，committed == emit 数 == ground truth 消息数；
//! 3. 确定性：同一字节两次解析，事件流与报告完全一致；
//! 4. 元数据透传：native_id == message id、role/text 原样（text part 按
//!    time_created 排序以 `\n` 拼接）、timestamp 恒 None；
//! 5. 会话身份：session_native_id == 首条消息的 session，cwd 同源保留，
//!    多会话 fail-closed 为 Ambiguous；
//! 6. probe 对任意字节永不 panic：Ok 时 confidence 非 Ambiguous 且 variant 恒为自身；
//! 7. golden fixture 的 seeded 确定性变异（截断 / 插入 / 删除 / 翻转字节）下
//!    parse 永不 panic：Ok 则消息字段合法（committed==emit、正文非空、span 恒
//!    None），Err 则 recoverable 由上层回滚；变异源字节前后不变
//!    （RFC-0002 §7，经 testkit `assert_read_only`）。
//!
//! 零新依赖（repo 惯例）：本地 xorshift64* PRNG + 固定种子表；rusqlite 是 crate
//! 自身依赖。断言信息一律携带 seed，失败可用该 seed 单独重放；不落盘（临时库
//! 用后即删）、不联网。

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};

use agent_session_grep_ports::MetadataResolution;
use agent_session_grep_ports::{
    CanonicalEventSink, Confidence, MessageEvent, ParseReport, ProviderAdapter,
};
use agent_session_grep_provider_opencode::OpenCodeAdapter;
use agent_session_grep_testkit::assert_read_only;
use rusqlite::{Connection, params};

const VARIANT_ID: &str = "opencode/sqlite-v1";
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/basic.db");

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
    "opencode 库自检",
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

/// 一条预期产出的消息。
struct ExpectedMessage {
    native_id: String,
    role: String,
    text: String,
}

/// 一个生成的 OpenCode 库用例：序列化字节 + 全部预期值 + 语料覆盖度标志。
struct Case {
    bytes: Vec<u8>,
    expected: Vec<ExpectedMessage>,
    session_id: Option<String>,
    multi_session: bool,
    cwd: Option<String>,
    saw_system_role: bool,
    saw_dropped_data: bool,
    expected_skipped: usize,
    saw_tool_part: bool,
    saw_ws_only: bool,
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

/// 进程内唯一临时路径：pid + 原子计数器，避免并行测试互相截断。
fn temp_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "asg-prop-opencode-{}-{}-{tag}.db",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// 把内存库序列化成字节（与 crate 单测同款 VACUUM INTO 路径）。
fn vacuum_to_bytes(conn: &Connection) -> Vec<u8> {
    let path = temp_path("build");
    conn.execute_batch(&format!("VACUUM INTO '{}'", path.display()))
        .expect("VACUUM INTO 必须成功");
    let bytes = std::fs::read(&path).expect("read vacuumed db");
    let _ = std::fs::remove_file(&path);
    bytes
}

/// 一条计划消息：id / session / data 形态 / 时间 / 判定后的产出正文。
struct PlannedMsg {
    id: String,
    session: String,
    /// data 列渲染值；None 表示写入坏 JSON（adapter 会整行丢弃）。
    data: Option<String>,
    /// 该行若被 adapter 读出，role 的实际值（data 合法时 == 渲染的角色）。
    role: String,
    time: i64,
    emitted_text: Option<String>,
}

/// 生成器把"计划语义"与 adapter 的查询口径做同源判定：
/// `data` 是 SQL NULL 或 `$.role` 不是字符串 → 该行计入 skipped；
/// part 同理（`$.type` != 'text' 或 `$.text` 不是字符串 → 不进正文）。
fn build_case(seed: u64, with_big_field: bool) -> Case {
    let mut rng = XorShift64Star::new(seed);
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(
        "CREATE TABLE session (id TEXT PRIMARY KEY, title TEXT, directory TEXT, time_created INTEGER, time_updated INTEGER);
         CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT, time_created INTEGER);
         CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, data TEXT, time_created INTEGER);",
    )
    .expect("create schema");

    // 会话：1..=3 个；directory 存在与否决定 cwd pair 是否可观察。
    let n_sessions = 1 + rng.below(3);
    let mut session_dirs: Vec<(String, Option<String>)> = Vec::with_capacity(n_sessions);
    for s in 0..n_sessions {
        let id = format!("ses-{seed:016x}-{s}");
        let dir = rng.chance(1, 2).then(|| "/synthetic/workspace".to_string());
        let title = rng.chance(1, 2).then(|| "synthetic title".to_string());
        conn.execute(
            "INSERT INTO session (id, title, directory, time_created, time_updated) VALUES (?1, ?2, ?3, 0, 0)",
            params![id, title, dir],
        )
        .expect("insert session");
        session_dirs.push((id, dir));
    }

    // 消息与 part 计划：先定语义，再落库。
    let n_msgs = 2 + rng.below(9);
    let mut planned: Vec<PlannedMsg> = Vec::with_capacity(n_msgs);
    let mut saw_system_role = false;
    let mut saw_dropped_data = false;
    let mut expected_skipped = 0;
    let mut saw_tool_part = false;
    let mut saw_ws_only = false;
    let mut time_counter: i64 = 0;

    for m in 0..n_msgs {
        time_counter += 1;
        let id = format!("msg-{seed:016x}-{m}");
        let session = session_dirs[rng.below(n_sessions)].0.clone();
        // data 形态：合法 JSON 角色（多数）/ 坏 JSON / 非字符串角色。
        let (data, role) = match rng.below(10) {
            0..=6 => {
                let role = rng.pick(&["user", "assistant", "system", "user", "assistant"]);
                if role == "system" {
                    saw_system_role = true;
                }
                (Some(format!(r#"{{"role":"{role}"}}"#)), role.to_string())
            }
            7 => {
                saw_dropped_data = true;
                expected_skipped += 1;
                (None, String::new()) // SQL NULL: counted as skipped
            }
            8 => {
                saw_dropped_data = true;
                expected_skipped += 1;
                (Some(r#"{"role":42}"#.to_string()), String::new()) // 非字符串角色：丢弃
            }
            _ => (Some(r#"{"role":"tool"}"#.to_string()), "tool".to_string()),
        };

        // parts：0..=3 个 text part（可能空白/超大）+ 0..=2 个 tool part。
        let n_parts = rng.below(4);
        let mut parts: Vec<(String, i64)> = Vec::new();
        for p in 0..n_parts {
            time_counter += 1;
            let part_id = format!("part-{seed:016x}-{m}-{p}");
            let text = if with_big_field && m == 0 && p == 0 {
                big_text()
            } else {
                match rng.below(10) {
                    0..=5 => gen_text(&mut rng),
                    6..=7 => "   ".to_string(), // 空白正文：进 parts 但整条消息被 trim 跳过
                    _ => String::new(),         // 空正文：不进 parts
                }
            };
            conn.execute(
                "INSERT INTO part (id, message_id, data, time_created) VALUES (?1, ?2, ?3, ?4)",
                params![
                    part_id,
                    id,
                    format!(r#"{{"type":"text","text":"{}"}}"#, escape_json(&text)),
                    time_counter
                ],
            )
            .expect("insert text part");
            if !text.is_empty() {
                parts.push((text, time_counter));
            }
        }
        for t in 0..rng.below(3) {
            saw_tool_part = true;
            time_counter += 1;
            let part_id = format!("tool-{seed:016x}-{m}-{t}");
            conn.execute(
                "INSERT INTO part (id, message_id, data, time_created) VALUES (?1, ?2, ?3, ?4)",
                params![
                    part_id,
                    id,
                    format!(
                        r#"{{"type":"tool_use","name":"synthetic","input":{}}}"#,
                        rng.below(3)
                    ),
                    time_counter
                ],
            )
            .expect("insert tool part");
        }

        // ground truth：text part 按 time 排序拼接；role 合法且整体非空白才产出。
        let mut sorted = parts.clone();
        sorted.sort_by_key(|(_, t)| *t);
        let joined = sorted
            .iter()
            .map(|(t, _)| t.clone())
            .collect::<Vec<_>>()
            .join("\n");
        let mut emitted_text = None;
        if matches!(role.as_str(), "user" | "assistant") {
            if joined.trim().is_empty() {
                if !joined.is_empty() {
                    saw_ws_only = true;
                }
            } else {
                emitted_text = Some(joined);
            }
        }

        let time = time_counter;
        conn.execute(
            "INSERT INTO message (id, session_id, data, time_created) VALUES (?1, ?2, ?3, ?4)",
            params![id, session, data, time],
        )
        .expect("insert message");

        planned.push(PlannedMsg {
            id,
            session,
            data,
            role,
            time,
            emitted_text,
        });
    }

    // 属性前提是"存在有效消息"；极端种子下若一条都产不出则强制补一条。
    if !planned
        .iter()
        .any(|m| m.data.is_some() && m.emitted_text.is_some())
    {
        time_counter += 1;
        conn.execute(
            "INSERT INTO message (id, session_id, data, time_created) VALUES (?1, ?2, ?3, ?4)",
            params![
                format!("forced-{seed:016x}"),
                session_dirs[0].0,
                r#"{"role":"user"}"#,
                time_counter
            ],
        )
        .expect("insert forced message");
        conn.execute(
            "INSERT INTO part (id, message_id, data, time_created) VALUES (?1, ?2, ?3, ?4)",
            params![
                format!("forced-part-{seed:016x}"),
                format!("forced-{seed:016x}"),
                r#"{"type":"text","text":"forced valid record"}"#,
                time_counter
            ],
        )
        .expect("insert forced part");
        planned.push(PlannedMsg {
            id: format!("forced-{seed:016x}"),
            session: session_dirs[0].0.clone(),
            data: Some(r#"{"role":"user"}"#.to_string()),
            role: "user".to_string(),
            time: time_counter,
            emitted_text: Some("forced valid record".to_string()),
        });
    }

    let bytes = vacuum_to_bytes(&conn);

    // ground truth：adapter 按 time_created ASC 全库排序，坏 data 行被丢弃。
    let mut emitted: Vec<PlannedMsg> = planned
        .into_iter()
        .filter(|m| m.data.is_some() && m.emitted_text.is_some())
        .collect();
    emitted.sort_by_key(|m| m.time);
    let expected: Vec<ExpectedMessage> = emitted
        .iter()
        .map(|m| ExpectedMessage {
            native_id: m.id.clone(),
            role: m.role.clone(),
            text: m.emitted_text.clone().expect("filtered"),
        })
        .collect();

    let session_id = emitted.first().map(|m| m.session.clone());
    let distinct: std::collections::BTreeSet<&str> =
        emitted.iter().map(|m| m.session.as_str()).collect();
    let multi_session = distinct.len() > 1;
    let cwd = session_id.as_ref().and_then(|sid| {
        session_dirs
            .iter()
            .find(|(id, _)| id == sid)
            .and_then(|(_, dir)| dir.clone())
            .filter(|d| !d.trim().is_empty())
    });

    Case {
        bytes,
        expected,
        session_id,
        multi_session,
        cwd,
        saw_system_role,
        saw_dropped_data,
        expected_skipped,
        saw_tool_part,
        saw_ws_only,
    }
}

/// 最小 JSON 字符串转义（只处理 `"` 与 `\`，测试池其余字符无需转义）。
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_case(seed: u64, bytes: &[u8]) -> (ParseReport, Vec<Captured>) {
    let mut sink = CollectingSink::default();
    let report = OpenCodeAdapter::new()
        .parse(bytes, &mut sink)
        .unwrap_or_else(|e| panic!("seed={seed}: 合法生成的 opencode 库 parse 失败：{e}"));
    (report, sink.messages)
}

/// 逐固定种子运行 body；index 0 的迭代携带 ~256 KiB 大字段。
fn for_each_seed(mut body: impl FnMut(u64, &Case)) {
    for (idx, &seed) in fixed_seeds().iter().enumerate() {
        let case = build_case(seed, idx == 0);
        body(seed, &case);
    }
}

/// 性质 1：SQLite 没有行内字节坐标——所有消息 span 恒 None。
#[test]
fn prop_spans_are_always_none() {
    for_each_seed(|seed, case| {
        let (_, captured) = parse_case(seed, &case.bytes);
        for got in &captured {
            assert_eq!(
                got.span, None,
                "seed={seed} seq={}: opencode 为 SQLite 源，不得归因行内 span",
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
        assert_eq!(
            report.skipped, case.expected_skipped,
            "seed={seed}: malformed roles must be counted"
        );
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

/// 性质 4：native_id == message id、role/text 原样（text part 按 time 拼接）、
/// timestamp 恒 None、无 parent、无 sidechain。
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
                got.native_id, want.native_id,
                "seed={seed} seq={seq}: native_id 必须等于 message id"
            );
            assert_eq!(
                got.role, want.role,
                "seed={seed} seq={seq}: role 必须原样透传"
            );
            assert_eq!(
                got.text, want.text,
                "seed={seed} seq={seq}: 文本必须等于 text part 按 time 的 \\n 拼接"
            );
            assert_eq!(
                got.timestamp, None,
                "seed={seed} seq={seq}: opencode 不提取消息级时间戳"
            );
            assert_eq!(
                got.parent_native_id, None,
                "seed={seed} seq={seq}: opencode 无 threading 边"
            );
            assert!(
                !got.is_sidechain,
                "seed={seed} seq={seq}: opencode 无 sidechain"
            );
        }
    });
}

/// 性质 5：会话身份——session_native_id == 首条消息的 session；cwd 从 session
/// 表同源保留；多会话时 multi_session 置位且 provider_session_id fail-closed。
#[test]
fn prop_session_identity_matches_ground_truth() {
    for_each_seed(|seed, case| {
        let (report, _) = parse_case(seed, &case.bytes);
        assert_eq!(
            report.session_native_id, case.session_id,
            "seed={seed}: session_native_id 必须等于首条消息的 session"
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
                "seed={seed}: 无消息时 provider_session_id 必须 Missing"
            ),
        }
        match case.cwd.as_deref() {
            Some(cwd) => {
                assert_eq!(
                    report.session_observation.original_working_directory,
                    MetadataResolution::Resolved(cwd.to_string()),
                    "seed={seed}: cwd 必须从 session 表同源保留"
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

/// 语料覆盖度：64 个固定种子必须实际exercise过 system 角色、坏 data 行、
/// tool part、空白正文消息——防止生成器退化成空转语料。
#[test]
fn prop_corpus_coverage_is_not_degenerate() {
    let mut saw_system = false;
    let mut saw_dropped = false;
    let mut saw_tool = false;
    let mut saw_ws = false;
    let mut saw_multi = false;
    let mut saw_single = false;
    for (i, seed) in fixed_seeds().iter().copied().enumerate() {
        let case = build_case(seed, i == 0);
        saw_system |= case.saw_system_role;
        saw_dropped |= case.saw_dropped_data;
        saw_tool |= case.saw_tool_part;
        saw_ws |= case.saw_ws_only;
        saw_multi |= case.multi_session;
        saw_single |= !case.multi_session;
        assert!(
            !case.expected.is_empty(),
            "seed={seed}: 每个用例必须至少含一条有效消息"
        );
    }
    assert!(
        saw_system && saw_dropped && saw_tool && saw_ws && saw_multi && saw_single,
        "生成器语料退化：system={saw_system} dropped={saw_dropped} tool={saw_tool} \
         ws={saw_ws} multi={saw_multi} single={saw_single}"
    );
}

/// 只读契约：合成库的 probe 与 parse 前后字节长度与 BLAKE3 指纹不变
/// （RFC-0002 §7 的可执行守护）。
#[test]
fn prop_probe_and_parse_are_read_only() {
    for_each_seed(|seed, case| {
        let report = assert_read_only(&case.bytes, |src| {
            let mut sink = CollectingSink::default();
            OpenCodeAdapter::new().parse(src, &mut sink)
        })
        .unwrap_or_else(|e| panic!("seed={seed}: 合成库 parse 失败：{e}"));
        assert!(report.committed > 0, "seed={seed}: 合成库必须产出消息");
        let _ = assert_read_only(&case.bytes, |src| OpenCodeAdapter::new().probe(src));
    });
}

/// probe 对任意字节永不 panic：纯随机 / 随机 ASCII / 随机 JSON 状文本 /
/// golden 随机截断。Ok 时 confidence 非 Ambiguous 且 variant 恒为自身。
#[test]
fn prop_probe_never_panics_on_arbitrary_bytes() {
    let adapter = OpenCodeAdapter::new();
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
                    // 假 SQLite 头 + 随机尾：magic 通过但打开必败。
                    let mut b = b"SQLite format 3\0".to_vec();
                    let n = rng.below(1024);
                    b.extend((0..n).map(|_| rng.next_u64() as u8));
                    b
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

/// 合成库上的 probe：不 panic、两次调用结果一致、恒 Ok(Confirmed)（三表齐备）
/// 且 variant 为自身。
#[test]
fn prop_probe_on_generated_dbs_confirms_own_variant() {
    for_each_seed(|seed, case| {
        let adapter = OpenCodeAdapter::new();
        let a = adapter.probe(&case.bytes);
        let b = adapter.probe(&case.bytes);
        assert_eq!(a, b, "seed={seed}: probe 两次调用必须确定一致");
        let r = a.unwrap_or_else(|e| panic!("seed={seed}: 合成库 probe 必须成功：{e}"));
        assert_eq!(
            r.confidence,
            Confidence::Confirmed,
            "seed={seed}: 三表齐备必须 Confirmed"
        );
        assert_eq!(
            r.variant_id, VARIANT_ID,
            "seed={seed}: probe 必须报告自身 variant"
        );
    });
}

/// golden fixture 的 seeded 确定性变异（SQLite 是二进制源：截断 / 插入 / 删除 /
/// 翻转字节，无行级操作）。
fn mutate_bytes(rng: &mut XorShift64Star, base: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    match rng.below(5) {
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
        _ => {
            // 翻转一个 1..=24 字节的连续区段。
            let pos = rng.below(out.len());
            let n = (1 + rng.below(24)).min(out.len() - pos);
            for b in &mut out[pos..pos + n] {
                *b ^= 0xFF;
            }
        }
    }
    out
}

/// 变异语料上的 parse：永不 panic；Err 即 recoverable 拒绝（上层回滚 staging，
/// SQLite 打开失败是 StructuralFatal）；Ok 则绝不 partial commit——
/// committed == emit 数、seq 连续、span 恒 None、正文非空、角色合法。
/// 同时 probe 变异字节不 panic，且源字节在 parse 前后不变（RFC-0002 §7）。
#[test]
fn prop_golden_mutations_never_panic_and_output_stays_legal() {
    let fixture = std::fs::read(FIXTURE_PATH).expect("read golden fixture");
    let adapter = OpenCodeAdapter::new();

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
                assert_eq!(
                    m.span, None,
                    "seed={seed} op={op}: seq={} SQLite 不得归因行内 span",
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
