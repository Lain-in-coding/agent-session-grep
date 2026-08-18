# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.json` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.json` 为**人工手写的合成 JSON 数组文档**（单文件
`api_conversation_history.json`，非行式），不基于任何真实会话记录做删减或脱敏。
字节即权威：UTF-8（无 BOM）、LF 行尾，BLAKE3 pin 在 `basic.expected.json`
（`cdf89cc8c2ea720591e36776b59ece29102b4a73e12acee75ca9007f7cf5bd46`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐条覆盖

顶层为 message 对象数组（`role`/`content`/`timestamp`）。

| 条目 | 内容 | 覆盖点 |
|------|------|--------|
| 0 | `role:"user"`，字符串 content | 用户消息 |
| 1 | `role:"assistant"`，字符串 content | 助手消息 |
| 2 | `role:"system"` | 系统消息跳过 |
| 3 | `role:"user"`，数组 content | `{type:"text",text}` block 以 `\n` 拼接 |
| 4 | `role:"assistant"`，空 content | 空正文跳过 |
| 5 | `role:"assistant"`，字符串 content + `timestamp` | 消息级时间戳透传 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Cline `api_conversation_history.json`（`~/.cline/data/tasks/*/`，单 JSON 数组）
的格式观察，仅复用结构：message 对象带 `role` 与 `content`（字符串或 content
part 数组）。适配器不产出字节 span——single JSON 数组不是行式格式，数组下标
pseudo-span 违反 `MessageEvent.span` 的字节区间契约，已移除（`span: None`），
capability.rs `source_span` 诚实声明为 `unsupported`。

## 脱敏与合规声明

- **不含任何真实数据**：时间戳为 `2026-01-01T00:01:00Z` 固定基准、正文为自述性
  合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

**N/A**：单文档 JSON 数组无行式字节坐标，adapter 全部消息 `span: None`
（golden 测试 `golden_messages_carry_no_byte_span`）。
