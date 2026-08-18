# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.jsonl` 为**逐行人工手写的合成数据**，不基于任何真实会话记录做删减或脱敏。
字节即权威：UTF-8（无 BOM）、LF 行尾，BLAKE3 pin 在 `basic.expected.json`
（`91c89b552a91af07963822c50ec3ddb5dba3ae7ffb9ae439b9ada6aac3d72276`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐行覆盖

每行一个 CodeBuddy CLI JSONL 记录；`type:"message"` 为对话记录，`role`/`content`
在顶层（OpenAI 风格）。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `type:"message"`，`role:"user"`，content 恰为 `"code"` | 根启动关键字消息被过滤（launcher token，非真实请求） |
| 2 | `type:"message"`，`role:"user"`，`sessionId` | 用户消息；会话身份逐行收集 |
| 3 | `type:"message"`，`role:"assistant"` 数组 content | `{type:text}` block 以 `\n` 拼接 |
| 4 | `type:"meta"` | 非 message 类型跳过 |
| 5 | `type:"message"`，`role:"system"` | 非对话角色跳过 |
| 6 | 非 JSON 行 | 破损行 → `skipped+1` + 诊断 |
| 7 | `type:"message"`，CJK + `timestamp` | 多字节 span；顶层时间戳透传 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 CodeBuddy CLI session JSONL 的格式观察，仅复用结构：`type:"message"` 携带
顶层 `role`（user/assistant/system）与 `content`（字符串或 `{type:"text",text}`
数组）及 `sessionId`；启动关键字 root 消息内容为字面 `"code"`（PRD 证据，过滤）。
分派与 `"code"` 过滤为 idea-level 借鉴 AgentRecall（MIT），未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：sessionId 为 `sess-1` 固定假值、路径为 `/work` 占位符、
  时间戳为 `2026-01-01T00:00:0NZ` 固定基准、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

行式 JSONL：每个 span 覆盖"某一整行去掉行尾符"，golden 测试
`golden_spans_slice_back_to_exact_source_lines` 逐字节校验切片并核对
`type:"message"` + 顶层 `role` 与消息角色一致。
