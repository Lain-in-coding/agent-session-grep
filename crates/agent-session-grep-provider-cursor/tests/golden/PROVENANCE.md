# Golden fixture 来源声明（PROVENANCE）

> 依据 `docs/security/FIXTURE-REDACTION-POLICY.md`：合成优先、禁止真实 transcript、
> fixture 目录必须附本声明。

## fixture_revision

- `basic.db` — revision 1（2026-08-16 引入）。
- 格式修复必须新增 fixture 而非只改 parser（政策 §Provider fixture 要求）。

## 构造方式

`basic.db` 为 **SQLite 二进制 fixture**，由本目录 `generate_fixture.py`（Python 3
标准库 `sqlite3`）生成：先 `CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value
TEXT)`，再插入两个 key 的 JSON 值，`commit` 后关闭——JSON 内容逐字见生成脚本，
是唯一来源。**纯合成**：不基于任何真实 `state.vscdb` 做删减或脱敏。字节即权威，
BLAKE3 pin 在 `basic.expected.json`
（`26556f79bc187baa0169ca383fd411e086bdad2438301a40a4a8f15e4d857ab9`）。

再生（仅审计用；committed 字节与 pinned BLAKE3 才是契约）：
```text
python crates/agent-session-grep-provider-cursor/tests/golden/generate_fixture.py
```

## 逐 key 覆盖

| key | 内容 | 覆盖点 |
|-----|------|--------|
| `workbench.panel.aichat.view.aichat.chatdata` | 1 个 tab（`tab-1`），3 个 bubble | bubble 按 `timingInfo.startTime` 排序；`text` 优先于 `rawText`；无 `text` 的 bubble 用 `rawText`；tab `createdAt` 排序 |
| `aiService.prompts` | 1 个 conversation（`conv-a`），2 个 prompt | prompt/response 展开为 user+assistant；同 conversation 按 `createdAt` 排序；空 response 跳过；第二会话 → `multi_session` fail-closed |

## 编码的真实格式知识（仅字段名与封套形状，无真实内容）

来自 Cursor `state.vscdb`（VS Code workspaceStorage ItemTable KV）的格式观察，
仅复用结构：chatdata key 的 JSON 文档含 `tabs[]`（`id`/`createdAt`/`bubbles[]`
含 `type`/`text`/`rawText`/`timingInfo.startTime`）；prompts key 的 JSON 数组含
`{prompt, response, createdAt, conversationId}`。形状适配自 hstry（MIT）的
idea-level 结构，未复制任何字节。

## 脱敏与合规声明

- **不含任何真实数据**：tab/prompt/conversation id 为 `tab-1`/`pN`/`conv-a` 固定
  假值、时间戳为 `101`–`201` 合成整数、正文为自述性合成文案；
- 无人名、邮箱、token、密钥、真实项目名或真实主机路径；
- 未从任何同类项目复制 fixture（政策 §许可证边界）。

## span round-trip

**N/A**：SQLite 源无文件内字节坐标，adapter 全部消息 `span: None`
（golden 测试 `golden_messages_carry_no_byte_span`）。只读契约由
`assert_read_only` 守护（adapter 以 `SQLITE_OPEN_READONLY` 打开临时副本）。
