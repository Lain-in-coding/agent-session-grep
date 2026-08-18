# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.jsonl` 为**逐行人工手写的合成数据**，不基于任何真实会话记录做删减或脱敏。
字节即权威：UTF-8（无 BOM）、LF 行尾，BLAKE3 pin 在 `basic.expected.json`
（`f49913760c18a993159225ff5987bbd1f949e1167e5ade25e04088aa3a114dff`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐行覆盖

每行一个 Qoder transcript JSONL 记录；`type` 即角色判别。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `type:"session_meta"`，顶层 `session_id`+`cwd`+`timestamp` | 会话身份 + cwd pair 上报 |
| 2 | `type:"user"`，`message.content` 字符串 | 用户消息；span |
| 3 | `type:"assistant"`，`message.content` 数组 | `{type:text}` block 以 `\n` 拼接 |
| 4 | `type:"progress"` | 非对话记录跳过 |
| 5 | `type:"tool_use"` | 非对话记录跳过 |
| 6 | `type:"tool_result"` | 非对话记录跳过 |
| 7 | 非 JSON 行 | 破损行 → `skipped+1` + 诊断 |
| 8 | `type:"user"`，CJK + `message.timestamp` | 多字节 span；消息内时间戳透传 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Qoder transcript JSONL（`~/.qoder/projects/<project>/transcript/*.jsonl`）的
格式观察，仅复用结构：`type:"session_meta"` 头（`session_id`/`cwd` 容错匹配）、
`type:"user"`/`type:"assistant"` 记录其 `type` 即角色、`message.content` 为正文；
`progress`/`tool_use`/`tool_result` 非对话。身份字段 lenient 匹配（顶层或嵌套
`session_meta` 对象）。

## 脱敏与合规声明

- **不含任何真实数据**：session id 为 `sess-1` 固定假值、路径为 `/work/placeholder`
  占位符、时间戳为 `2026-01-01T00:00:0NZ` 固定基准、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

行式 JSONL：每个 span 覆盖"某一整行去掉行尾符"，golden 测试
`golden_spans_slice_back_to_exact_source_lines` 逐字节校验切片并核对记录 `type`
与消息角色一致。
