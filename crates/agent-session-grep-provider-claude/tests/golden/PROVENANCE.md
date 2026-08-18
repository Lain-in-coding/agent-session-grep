# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.jsonl` — revision 1（2026-07-26 首次引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.jsonl` 为**逐行人工手写的合成数据**，不基于任何真实会话记录做删减或脱敏；
无生成脚本——8 行内容全部在代码评审中可见即全部来源。字节即权威：文件为
UTF-8（无 BOM）、LF 行尾，`basic.expected.json` 中 pin 了全文件字节的 BLAKE3
指纹，配合根 `.gitattributes` 的 `-text` 规则防止 checkout 时的行尾改写。

## 逐行覆盖

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `type:"user"` 根消息 | 首条记录携带 `sessionId`；`parentUuid:null` 根；字符串形态 `content`；additive 未知字段（`userType`/`cwd`/`version`）被忽略 |
| 2 | `type:"assistant"` | `parentUuid` 链；block 数组形态 `content`；无 `text` 的 `tool_use` block 被过滤；CJK + emoji（多字节 span） |
| 3 | `type:"summary"` | 非对话记录：静默略过，不计 skipped |
| 4 | 空行 | 空白行静默略过，但参与字节偏移 |
| 5 | 截断的 JSON | 破损行 → record_recoverable：skipped+1 + 诊断，不中止解析 |
| 6 | `type:"user"`, `isSidechain:true` | sidechain 标记；RTL（阿拉伯文/希伯来文）混排文本 |
| 7 | `message.role:"tool"` | tool 角色透传（role 取自 `message.role` 而非顶层 `type`）；`tool_result` block 的 `content` 字段（工具输出）并入检索文本 |
| 8 | `type:"assistant"`，无 `timestamp` | timestamp 缺失 → `null`；JSON 转义（`\"`、`\\`）解码后与 span 原始字节不同 |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自对 Claude Code JSONL transcript 格式的观察，仅复用**结构**：

- 每行一个 JSON 对象；对话记录封套字段：`type`、`uuid`、`parentUuid`、
  `sessionId`、`timestamp`（ISO-8601 UTC）、`isSidechain`，另有 `userType`/
  `cwd`/`version` 等 additive 字段；
- `message.content` 两种形态：纯字符串，或 block 数组（`{"type":"text","text":…}`、
  `tool_use`、`tool_result` 等；`text` 字段与 `tool_result` 的 `content` 字段
  （字符串或 text block 数组）可检索）；
- 非对话行如 `{"type":"summary","summary":…,"leafUuid":…}`。

## 脱敏与合规声明

- **不含任何真实数据**：uuid 为 `00000000-0000-4000-8000-00000000000N` 型固定
  假值，sessionId 为 `aaaaaaaa-…` 型固定假值，路径为 `C:\placeholder\project`
  占位符，时间戳为 `2026-01-01T00:00:0NZ` 固定基准，正文全部为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。
