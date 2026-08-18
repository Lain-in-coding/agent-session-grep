# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.jsonl` 为**逐行人工手写的合成数据**，不基于任何真实会话记录做删减或脱敏。
字节即权威：UTF-8（无 BOM）、LF 行尾，BLAKE3 pin 在 `basic.expected.json`
（`2e21aa04438333b7f3968f816a5357439afe521fe2df501573334b066fa2e605`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐行覆盖

每行一个 Antigravity step 记录（`step_index` + `source` + `type` + `created_at`）。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `USER_EXPLICIT`/`USER_INPUT`，RFC3339 时间戳 | 用户消息；时间戳透传；span |
| 2 | `SYSTEM`/`CONVERSATION_HISTORY` | 系统上下文步骤永不作为 user/assistant 输出 |
| 3 | `MODEL`/`PLANNER_RESPONSE`，content+thinking | 助手消息（content 优先）；时间戳 |
| 4 | `MODEL`，content 为空、thinking 有值 | thinking 兜底为助手正文 |
| 5 | `USER_EXPLICIT`，非法时间戳 + CJK 文本 | 非法时间戳 → `null`；多字节 span |
| 6 | `MODEL`，content 与 thinking 均缺 | 空步骤跳过 |
| 7 | 非 JSON 行 | 破损行 → `skipped+1` + 诊断 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Antigravity CLI `transcript.jsonl`（`brain/<uuid>/.system_generated/logs/`）的
格式观察，仅复用结构：`step_index`、`source`（`USER_EXPLICIT`/`SYSTEM`/`MODEL`）、
`type`（`USER_INPUT`/`CONVERSATION_HISTORY`/`PLANNER_RESPONSE`）、`status`、
`created_at`（ISO-8601）、可选 `content`/`thinking`/`tool_calls`。只有显式
user/model 步骤是对话记录；`SYSTEM`（含 CONVERSATION_HISTORY dump）永不为消息。

## 脱敏与合规声明

- **不含任何真实数据**：step_index 为 0–5 固定序号、路径/项目为自述性合成文案、
  时间戳为 `2026-07-03T13:22:1NZ` 固定基准；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

行式 JSONL：每个 span 覆盖"某一整行去掉行尾符"，golden 测试
`golden_spans_slice_back_to_exact_source_lines` 逐字节校验切片并核对 `source`
种类（`USER_EXPLICIT`↔user、`MODEL`↔assistant）与消息角色一致。

## 已知限制（镜像到 AdapterManifest.known_limitations）

会话身份在 `brain/<uuid>` 目录名而非 transcript 文件内——parse 如实留缺
（`session_native_id` 为 null）并把该限制写入 diagnostics。
