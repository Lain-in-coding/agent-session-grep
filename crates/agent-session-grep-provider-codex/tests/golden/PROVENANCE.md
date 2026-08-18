# PROVENANCE — codex golden fixture

- **fixture_revision**: 1
- **政策依据**: `docs/security/FIXTURE-REDACTION-POLICY.md`（合成优先）。本目录所有
  fixture 均为**人工合成**，未复制任何真实 transcript 的字节；不含真实路径、人名、
  邮箱、token、密钥或项目名。ids / session_id / cwd / cli_version 全部是虚构值。

## 构造方式

`basic.jsonl` 依据 provider-codex adapter 已编码的 Codex rollout 格式知识手写而成
（格式知识来源：对真实 rollout 结构的观察记录，仅借用**字段名与封套形状**，不复制
任何内容字节）。文件为 UTF-8 无 BOM、LF 行尾、末尾带换行；字节即契约——BLAKE3
指纹钉在 `basic.expected.json` 的 `fixture_blake3`，根 `.gitattributes` 的 `-text`
规则负责禁止 git 换行转换。

`basic.expected.json` 由 `tests/golden.rs` 里的 ignored 再生辅助测试生成后人工审阅：

```
cargo test -p agent-session-grep-provider-codex --test golden -- --ignored --nocapture
```

fixture 若需合法变更，必须递增本文件的 `fixture_revision` 并重新生成 expected
（政策要求：格式修复新增 fixture，而非只改 parser）。

## 编码的格式知识（逐行）

统一封套 `{"timestamp","type","payload"}`，`timestamp` 在**外层**；`type` 取值
`session_meta` / `turn_context` / `event_msg` / `response_item` 等。

| 行 | 内容 | 覆盖点 |
|----|------|--------|
| 1 | `session_meta`（payload 含 `session_id`/`cwd`/`originator`/`cli_version`） | durable 会话 id 上报；该行不产生消息 |
| 2 | `turn_context` | 已知非对话封套类型，静默跳过 |
| 3 | `event_msg`/`user_message` | 用户消息的 UI **镜像**，必须被忽略（不重复计数） |
| 4 | `response_item`/`message`（user，CJK+emoji） | **权威**对话记录：`payload.id`/`role`/`content[]` |
| 5 | `response_item`/`reasoning` | 非 message 的 response_item，静默跳过 |
| 6 | `response_item`/`message`（assistant，两个 `output_text` 块） | 多 block 按序以 `\n` 拼接 |
| 7 | `event_msg`/`agent_message` | 助手消息的镜像，必须被忽略 |
| 8 | 截断的 JSON（模拟 torn write） | record_recoverable：skipped+1，不中断解析 |
| 9 | `response_item`/`message`（user，emoji） | 镜像穿插后计数仍准确；seq 连续 |

关键不变量：每条对话在真实 rollout 中出现**两次**（`response_item/message` 权威 +
`event_msg` 镜像），只有权威记录被提交；Codex 无 `parentUuid`（线性序列，parent 恒
null）、无 `isSidechain`。外层时间戳只证明 source occurrence 的封套形态；同一
native message 的复制记录可携带不同值，因此 canonical Message 时间戳为 null。
