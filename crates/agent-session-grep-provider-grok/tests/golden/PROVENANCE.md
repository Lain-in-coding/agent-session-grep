# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-08-16 引入）。
- `object-content.jsonl` — revision 1（2026-08-29 引入，见下"对象 content fixture"）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.jsonl` 为**逐行人工手写的合成数据**，不基于任何真实会话记录做删减或脱敏。
字节即权威：文件为 UTF-8（无 BOM）、LF 行尾，`basic.expected.json` 中 pin 了全文件
字节的 BLAKE3（`a7f85a455dd1986dcd6c81feed5aad02c830ed2b26a4e8f70fc03009a70232ef`），
配合根 `.gitattributes` 的 `-text` 规则防止 checkout 时行尾改写。

## 逐行覆盖

每行一个 ACP `session/update` 记录；`params.update.sessionUpdate` 判别 chunk 种类。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `user_message_chunk`，字符串 content，`_meta.promptIndex:0` | 用户消息开启；span 指向首 chunk 行 |
| 2 | `user_message_chunk`，同 `promptIndex:0` | 同 prompt 的 chunk 按序拼接成一条消息 |
| 3 | `agent_message_chunk`，content 为 `[{text}]` 数组 | block 数组以 `\n` 拼接；`promptId` 上报为会话身份 |
| 4 | `user_message_chunk`，content 含 `_meta.bashCommand` | 工具活动元 chunk 被跳过（非对话） |
| 5 | `user_message_chunk`，`promptIndex:1` | 新 prompt 开启新用户消息 |
| 6 | `agent_message_chunk`，纯空白 content | 空白文本 chunk 被跳过 |
| 7 | 非 JSON 行 | 破损行 → `skipped+1` + 诊断，不中止解析 |
| 8 | 未知 `sessionUpdate` 种类 | 未知种类静默跳过 |
| 9 | `user_message_chunk`，CJK 文本 | 多字节文本与 span 字节长度 |
| 10 | `agent_message_chunk`，`promptId:p1` | 助手消息；会话身份保持首个 `promptId` |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Grok Build `updates.jsonl`（ACP `session/update` 流）的格式观察，仅复用结构：

- 每行一个 JSON 记录，`params.update.sessionUpdate` 取值 `user_message_chunk` /
  `agent_message_chunk` / `rewind_marker` 等；`params._meta.promptIndex` /
  `params._meta.promptId` 分组；`rewind_marker` 的 `targetPromptIndex` 截断
  重建列表；content 为字符串或 `{text}` block 数组；
- 修复注记：adapter 的 `UpdateParams.meta` 字段此前缺少 `_meta` 显式 rename，
  `promptId`/`promptIndex` 从未被解析（会话身份静默丢失）。已加
  `#[serde(rename = "_meta")]` 对齐文档格式；本 fixture 用 `_meta` 如实覆盖该路径。

## 脱敏与合规声明

- **不含任何真实数据**：promptId 为 `p1` 固定假值、时间为 `2026-01-01T00:00:0NZ`
  固定基准、路径/工具命令为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

行式 JSONL：每个 span 覆盖"某一整行去掉行尾符"，golden 测试
`golden_spans_slice_back_to_exact_source_lines` 逐字节校验切片并核对 chunk 种类
与消息角色一致。

## 对象 content fixture（`object-content.jsonl`）

`basic.jsonl` 只覆盖裸字符串与 block 数组 content，未覆盖参考实现中使用的单对象
形态：`{"type":"text","text":"…"}`。因此 adapter 的 `grok_content_text` 对
真实对象形态返回空串，随后 `user_message_chunk` / `agent_message_chunk` 的
`continue` 将用户与助手正文一起静默丢弃；这一缺陷不改变任何既有 golden 输出。

`object-content.jsonl` 同为逐行人工手写的合成数据，UTF-8（无 BOM）、LF 行尾、371
字节，BLAKE3 pin 在 `object-content.expected.json`
（`5f6ad4805ecca9d437fcfa058bea1bc49544c2ce7ad0bc35ca8d8fd8ede7a41b`）。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `user_message_chunk`，content 为 `{"type":"text","text":…}` 对象 | 对象形态用户 chunk 必须进索引 |
| 2 | `agent_message_chunk`，content 为同形对象 | 对象形态助手 chunk 必须进索引 |

形状证据：fast-resume（MIT）`src/adapters/grok.rs` 测试
（`content: {"type":"text","text":…}`）与 Recall `src/adapters/grok.rs` 测试
（同形 `session/update` 记录）。**未复制任何真实内容**。
