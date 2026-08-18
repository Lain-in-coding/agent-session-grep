# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.jsonl` 为**逐行人工手写的合成数据**，不基于任何真实会话记录做删减或脱敏。
字节即权威：UTF-8（无 BOM）、LF 行尾，BLAKE3 pin 在 `basic.expected.json`
（`88b52e5020f303824ab3555f52e71ee605a40b80d29cc3e5e253c7c4b9d4ba33`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐行覆盖

每行一个 Pi session JSONL 记录；`type` 判别（`session` / `message` / 其它）。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `type:"session"`，含 `id`+`cwd`+`timestamp` | 会话身份 + cwd pair 上报 |
| 2 | `type:"message"`，user 字符串 content | 用户消息；span |
| 3 | `type:"message"`，assistant 数组 content | `{type:text}` block 以 `\n` 拼接 |
| 4 | `type:"session_info"` | 非对话类型跳过 |
| 5 | `type:"compaction"` | 压缩记录跳过 |
| 6 | `type:"message"`，空 content | 空正文跳过 |
| 7 | 非 JSON 行 | 破损行 → `skipped+1` + 诊断 |
| 8 | `type:"message"`，CJK + message.timestamp | 多字节 span；消息内时间戳透传 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Pi session JSONL 的格式观察，仅复用结构：`type:"session"` 头（`id`/`cwd`/
`timestamp`）、`type:"message"` 包裹 `message.role`（user/assistant）与
`message.content`（字符串或 `{type:"text",text}` 数组）；`session_info`/
`compaction`/`custom_message` 非对话。内容抽取与类型分发适配自 fast-resume（MIT）
的 idea-level 结构，未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：session id 为 `sess-1` 固定假值、路径为 `/home/user/proj`
  占位符、时间戳为 `2026-01-01T00:00:0NZ` 固定基准、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

行式 JSONL：每个 span 覆盖"某一整行去掉行尾符"，golden 测试
`golden_spans_slice_back_to_exact_source_lines` 逐字节校验切片并核对
`type:"message"` + `message.role` 与消息角色一致。
