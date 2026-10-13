# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.md` — revision 1（2026-08-16 引入）。
- `multiline-prompt.md` — revision 1（2026-08-29 引入，见下"多行提示与裸标记 fixture"）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.md` 为**人工手写的合成 Markdown 聊天历史**（`.aider.chat.history.md` 的
单 run 形态），不基于任何真实会话记录做删减或脱敏。字节即权威：UTF-8（无 BOM）、
LF 行尾，BLAKE3 pin 在 `basic.expected.json`
（`b7f948bc73f1c26fde17ef98f920a84131978bd2bcfe32e4ca19e4be45912218`），根
`.gitattributes` 的 `-text` 规则防止行尾改写。

## 逐行覆盖

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `# aider chat started at <ts>` | run 头；时间戳作为会话身份 |
| 3 | `#### What is Rust?` | Markdown h4 → 用户消息 |
| 5 | 纯文本 | 助手回复 |
| 7 | `> Applied edit to src/main.rs` | blockquote 工具/编辑输出并入助手正文 |
| 9 | 纯文本 | 同一助手块续写 |
| 11 | `#### 中文问题` | CJK 用户消息；多字节派生 span |
| 13 | `答案是 42。` | 助手回复收尾 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Aider `.aider.chat.history.md` 的格式观察，仅复用结构：`# aider chat started
at <ts>` 分隔每次 run；`#### ` 前缀 → 用户提示；blockquote `> ` → 工具/编辑输出；
其余纯文本 → 助手回复。角色重建适配自 agentsview（MIT）的 idea-level 结构，
未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：会话时间戳为 `2026-01-01 12:00:00` 固定假值、文件路径为
  `src/main.rs` 占位符、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

**派生近似**（capability `source_span: derived`）：span 起点为消息块首行行首、
span 长度等于消息文本长度（`golden_spans_are_derived_approximations`），但 span
不保证逐字节切片等于文本（`#### `/`> ` 前缀与 trim 会偏移）——诚实反映 adapter
的实际 span 语义。

## 多行提示与裸标记 fixture（`multiline-prompt.md`）

`basic.md` 的每条 `#### ` 提示都只有一行，也没有裸 `####` / `>` 标记，于是三个
行前缀状态机缺陷在 golden 全绿的情况下一直存活：多行提示被切成 N 条单行消息、
裸标记被当成助手正文、紧跟提示的 blockquote 被算进 user 正文。

`multiline-prompt.md` 同为**人工手写的合成 Markdown**，字节即权威：UTF-8
（无 BOM）、LF 行尾、253 字节，BLAKE3 pin 在 `multiline-prompt.expected.json`
（`7eaf31bd75f56ac8f293be43764f00470be1c5b9c137d603a655856f0bcf8e7b`）。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `# aider chat started at <ts>` | run 头；时间戳作为会话身份 |
| 3–5 | **连续三行** `#### ` | aider 的多行提示形态：必须合成**一条** user 消息（跨行短语可检索）；第三行含 CJK + emoji（多字节派生 span） |
| 7 | 纯文本 | 助手回复 |
| 9 | 裸 `####` | aider 空输入标记：属 user 频道且不贡献正文，既不污染助手正文也不产出空消息 |
| 11–13 | `> …` / 裸 `>` / `> …` | 工具输出结束 user 块（不得记成 user 正文），按已声明限制折叠进 assistant；裸 `>` 在拼接后保留块内空行 |

预期产出：3 条消息（committed=3、skipped=0），角色依次 user / assistant / assistant。

### 编码的真实格式知识（仅字段名与形状）

`#### <text>` 与裸 `####`（空输入）、`> <text>` 与裸 `>`，以及"频道切换才产生
一条消息"的状态机语义。证据：agentsview（MIT）`internal/parser/aider.go` 的
`parseAiderTurns`（显式匹配 `line == "####"` 与 `line == ">"`，并注明 aider 对
空输入写 `#### `）。**未复制任何一方的 fixture 或代码文本**。

### 脱敏与合规声明

- 不含任何真实数据：会话时间戳为 `2026-01-02 09:00:00` 固定假值、文件路径为
  `src/placeholder.rs` / `src/placeholder_two.rs` 占位符、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径。
