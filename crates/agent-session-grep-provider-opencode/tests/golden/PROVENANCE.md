# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.db` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.db` 为 **SQLite 二进制 fixture**，由本目录 `generate_fixture.py`（Python 3
标准库 `sqlite3`）生成：先执行 `CREATE TABLE`，再按固定顺序 `INSERT` 全部合成行，
`commit` 后关闭——SQL 见生成脚本，是唯一来源。**纯合成**：不基于任何真实
`opencode.db` 做删减或脱敏。字节即权威，BLAKE3 pin 在 `basic.expected.json`
（`2668cbd406801399ff026c5d9c33c7ce9f5713d941b2554dd79d1263933cf8c4`）。

再生（仅审计用；committed 字节与 pinned BLAKE3 才是契约）：
```text
python crates/agent-session-grep-provider-opencode/tests/golden/generate_fixture.py
```

## 逐表覆盖

adapter（`src/lib.rs`）执行的三条查询：`session`（id/title/directory）、
`message`（id/session_id/data 含 `$.role`，按 time_created 排序）、`part`
（message_id/data 含 `$.type`/`$.text`，按 time_created 排序）。

| 表 | 内容 | 覆盖点 |
|----|------|--------|
| session | 1 行：`ses_1`，title `synthetic project`，directory `/work/placeholder` | 会话元数据 → cwd pair 上报 |
| message | `msg_1`(user)/`msg_2`(assistant)/`msg_3`(system)/`msg_4`(user) | 角色过滤：system 跳过 |
| part | `msg_1` 两条 text part | 多 part 按 `\n` 拼接 |
| part | `msg_2`/`msg_4` 各一条 | 单 part 文本；CJK 第二行 |
| （缺失） | `msg_3`（system）无 part | 无 part 的消息不会产出 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 OpenCode `opencode.db`（SQLite: session/message/part 表）的格式观察，仅复用
schema 形状与 `data` JSON 字段名（`role`/`type`/`text`）。schema 查询适配自
fast-resume（MIT）的 idea-level 结构，未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：session/message/part id 为 `ses_1`/`msg_N`/`part_N` 固定
  假值、目录为 `/work/placeholder` 占位符、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

**N/A**：SQLite 源无文件内字节坐标，adapter 全部消息 `span: None`
（golden 测试 `golden_messages_carry_no_byte_span`）。只读契约由
`assert_read_only` 守护（adapter 以 `SQLITE_OPEN_READONLY` 打开临时副本）。
