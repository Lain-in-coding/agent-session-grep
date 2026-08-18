# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.json` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.json` 为**人工手写的合成 JSON 文档**（单文件 `session_<id>.json`，非行式），
不基于任何真实会话记录做删减或脱敏。字节即权威：UTF-8（无 BOM）、LF 行尾，
BLAKE3 pin 在 `basic.expected.json`
（`1c6bb30025c23a798706fecba8c3761a1793d4c928cceaa938fe2252af13c6d1`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐条覆盖

顶层字段 `session_id`/`session_start`/`messages[]`。

| 条目 | 内容 | 覆盖点 |
|------|------|--------|
| 0 | `role:"system"` | 系统消息跳过 |
| 1 | `role:"user"`，自带 `timestamp` | 用户消息；消息级时间戳透传 |
| 2 | `role:"assistant"`，content 为空、reasoning 有值 | 空正文跳过 |
| 3 | `role:"assistant"`，content + reasoning | reasoning 包成 `[thinking]…[/thinking]` 块 |
| 4 | `role:"tool"` | 工具消息跳过 |
| 5 | `role:"user"`，无时间戳 | 时间戳回退到 `session_start` |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Hermes `session_<id>.json`（`~/.hermes/sessions/`）的格式观察，仅复用结构：
顶层 `session_id`、`session_start` 与 `messages[]`（`{role, content, reasoning?,
timestamp?, tool_call_id?, tool_calls?}`）。同目录 `<id>.jsonl` 只含部分近期状态，
adapter 忽略。消息提取适配自 hstry（MIT）的 idea-level 结构，未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：session_id 为 `hermes-sess-0001` 固定假值、时间戳为
  `2026-04-18T04:53:2Z` 固定基准、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

**N/A**：单文档 JSON 无行式字节坐标，adapter 全部消息 `span: None`
（golden 测试 `golden_messages_carry_no_byte_span`）。
