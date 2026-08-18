# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.jsonl` 为**逐行人工手写的合成数据**，不基于任何真实会话记录做删减或脱敏。
字节即权威：UTF-8（无 BOM）、LF 行尾，BLAKE3 pin 在 `basic.expected.json`
（`ad708d7bbcf1f4be7d3318d725493bc93b84f9fcd18352b9d61abc8eb2c81185`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐行覆盖

每行一个 Kimi wire.jsonl 记录；`type` 判别。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `context.append_message`，user 字符串 content | 用户消息；span |
| 2 | `context.append_message`，assistant 数组 content | `{text}` part 以 `\n` 拼接 |
| 3 | `context.append_loop_event` | loop/工具事件暂未解析，跳过 |
| 4 | `context.append_message`，system role | 非对话角色跳过 |
| 5 | 非 JSON 行 | 破损行 → `skipped+1` + 诊断 |
| 6 | `context.append_message`，空 content | 空正文跳过 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Kimi wire.jsonl 的格式观察，仅复用结构：`context.append_message` 包裹
`message.role`（user/assistant/system）与 `message.content`（字符串或 `{text}`
数组）；`context.append_loop_event` 承载 step/tool 事件（本切片 deferred）。
消息提取适配自 fast-resume（MIT）的 idea-level 结构，未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：uuid 为 `evt-1` 固定假值、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

行式 JSONL：每个 span 覆盖"某一整行去掉行尾符"，golden 测试
`golden_spans_slice_back_to_exact_source_lines` 逐字节校验切片并核对
`type:"context.append_message"` + `message.role` 与消息角色一致。
