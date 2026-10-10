# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-08-16 引入）。
- `v3-branched.jsonl` — revision 1（2026-08-27 引入，见下"v3 会话树 fixture"）。
- `thinking.jsonl` — revision 1（2026-08-29 引入，见下"thinking 语料 fixture"）。
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
`message.content`（字符串或 block 数组：`{type:"text",text}` 与
`{type:"thinking",thinking}` 两种承载正文的块，正文键名与块类型同名）；
`session_info`/`compaction`/`custom_message` 非对话。内容抽取与类型分发适配自
fast-resume（MIT）的 idea-level 结构，未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：session id 为 `sess-1` 固定假值、路径为 `/home/user/proj`
  占位符、时间戳为 `2026-01-01T00:00:0NZ` 固定基准、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

行式 JSONL：每个 span 覆盖"某一整行去掉行尾符"，golden 测试
`golden_spans_slice_back_to_exact_source_lines` 逐字节校验切片并核对
`type:"message"` + `message.role` 与消息角色一致。

## v3 会话树 fixture（`v3-branched.jsonl`）

覆盖政策 §Provider fixture 要求里的 **Branch/Retry/Fork** 一项：Pi 从格式
version 2 起逐条记录带 `id` 与显式 `parentId`，同一 `parentId` 的多个子记录即
分支（被放弃/重试的对话路径）。此前只有线性 v1 语料，v3 文件会被 probe 命中
但按线性解析且不留痕迹。

`v3-branched.jsonl` 同为**逐行人工手写的合成数据**，字节即权威：UTF-8（无 BOM）、
LF 行尾、1047 字节，BLAKE3 pin 在 `v3-branched.expected.json`
（`fc8c0db990ad43f00944393bcddae07ac2df48a8f454a230e2363c1a089cecd5`）。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `type:"session"`，含 `version:3` | v3 判别位（v1 无该键）+ 会话身份 + cwd pair |
| 2 | `type:"model_change"`，`parentId:null` | 非对话记录也是树节点；显式 null 根 |
| 3 | `type:"message"` user，`parentId` 指向行 2 | 血缘记录计数含跨类型父指针 |
| 4 | `type:"message"` assistant，父为行 3 | 保留分支；数组 content 以 `\n` 拼接 |
| 5 | `type:"message"` assistant，**父同为行 3** | **分支**：同 parentId 的第二个子记录 |
| 6 | `type:"message"` user，父为行 5 | 被放弃分支上的 CJK 正文（多字节 span） |
| 7 | `type:"session_info"`，父为行 4 | 非对话记录跳过但计入血缘 |

预期产出：4 条消息（committed=4、skipped=0），**两条分支的正文都进索引**——检索
完整性优先于线性还原；5 条记录带非空 `parentId`；每条消息 `native_id` 为空、
`parent_native_id` 为 `None`，并附一条会话树血缘诊断。为什么不发出 parent 边，
见 `crates/agent-session-grep-provider-pi/src/lib.rs` 模块文档与 capability.rs 的
pi 行（Pi 的 entry id 是仅文件内唯一的 32 位标记，而消息 native 身份是逐字采用
且无命名空间的）。

### 编码的真实格式知识（仅字段名与形状）

`version` 整数键在 `type:"session"` 头；逐条 `id`（真实 Pi 为 8 位十六进制，此处
用 `aa0000xx` 同形合成值）与 `parentId`（字符串或 `null`）；`model_change` /
`session_info` 等非对话类型。多源交叉：cc-sessions-viewer `src-tauri/src/agents/pi.rs`
的 `parse_entries`（v1/v2/v3 三版本兼容 + 病态树三检查）、fast-resume（MIT）
`src/adapters/pi.rs`、Recall `src/adapters/pi.rs`、hstry `adapters/pi/adapter.ts`、
agentsview `internal/parser/pi.go`。**未复制任何一方的 fixture 或代码文本**
（cc-sessions-viewer 无 LICENSE，仅 idea-level 借鉴）。

### 脱敏与合规声明

- 不含任何真实数据：session id 为 `sess-v3`、entry id 为 `aa0000xx` 序列、
  路径为 `/home/user/proj` 占位符、时间戳为 `2026-01-01T00:00:0NZ` 固定基准、
  正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径。

## thinking 语料 fixture（`thinking.jsonl`）

覆盖"assistant content 里的 `thinking` block"这一形状。`basic.jsonl` 与
`v3-branched.jsonl` 的 content 块一律是 `{type:"text"}`（由 golden
`golden_corpus_carries_no_tool_structure` 钉住），因此"thinking 正文被丢弃、
记录随后落进 `text.trim().is_empty()` 的 `continue` 分支而**既不 committed 也不
skipped**"这个缺陷在 golden 全绿的情况下存活了下来——报告里没有任何痕迹。

`thinking.jsonl` 同为**逐行人工手写的合成数据**，字节即权威：UTF-8（无 BOM）、
LF 行尾、1396 字节，BLAKE3 pin 在 `thinking.expected.json`
（`2b6c6a48af61d06094b5a06e0095d2a997d0671f010fd513cd2fc3c2ccb786e5`）。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `type:"session"`，含 `version:3` | 会话身份 + cwd pair |
| 2 | `type:"message"` user，`{type:"text"}` block | 基线用户消息 |
| 3 | `type:"message"` assistant，**只有 `thinking` block** | **本 fixture 的存在理由**：正文在 `thinking` 键上（另带 `thinkingSignature`），不在 `text` 上；此前整条记录无声消失 |
| 4 | `type:"message"` assistant，`thinking` + `text` + `toolCall` | thinking 与 text 按 block 顺序拼接（thinking 在前）；`toolCall` 块仍不进正文、不发 activity；CJK + emoji（多字节 span） |
| 5 | `type:"message"` assistant，空白 `thinking` + `text` | 纯空白 `thinking` 不产出空片段 |

预期产出：4 条消息（committed=4、skipped=0），零 activity。

### 编码的真实格式知识（仅字段名与形状）

`{"type":"thinking","thinking":…,"thinkingSignature":…}` 与
`{"type":"text","text":…,"textSignature":…}` 两种 block（正文键名与 block 类型
同名），以及 `{"type":"toolCall","id","name","arguments"}`。多源交叉：sessiongrep
`src/providers/pi.rs` 的 fixture、cc-sessions-viewer `src-tauri/src/agents/pi.rs`
的 `"thinking"` 分支（读 `.get("thinking")`，并丢弃空/纯空白值）、Recall
`src/adapters/pi.rs` 的 fixture。**未复制任何一方的 fixture 或代码文本**。

### 脱敏与合规声明

- 不含任何真实数据：session id 为 `11111111-2222-4333-8444-555555555555`、
  entry id 为 `aa0000xa` 序列、路径为 `/placeholder/project` 占位符、时间戳为
  `2026-01-03T00:00:0NZ` 固定基准、signature 为 `synthetic-*-signature-000N`
  固定假值、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径。
