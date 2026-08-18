# agent-session-grep 开源登顶路线图

> 治理记录(Governance Record)
>
> - decision_id: DOC-OPEN-SOURCE-ROADMAP
> - status: **Accepted**(owner 2026-08-15 逐项评审确认)
> - owner: QIN
> - approver: 项目最终验收人(owner)
> - 本文是执行总规划的持久化入口。

## 0.1 2026-08-17 阶段状态快照

本阶段（provider evidence / release-gate integration / release-gap 收口）已完成并合入 `main`，主体是 ToolActivity/schema-v12 落地；2026-08-17 收口追加 Robot facets schema、Web/MCP provider 一致性、16 行矩阵漂移守护、privacy 扫描强化、CI Python 套件接线等本地修复；2026-08-17/18 后续再追加：可选 `semantic-candle` 本地 Candle E5 后端 + `model import`/`model status` 离线模型缓存、handoff pack `tool_activity` 与权威 `role`/`is_sidechain` 投影、TUI 搜索分面控件（`m` sidechain / `k` tool-kind）、context 响应 `tool_activities` 投影、Provider Beta readiness 台账（`PROVIDER-BETA-READINESS.md`）；这表示“当前阶段的集成工作完成”，不表示项目已经满足公开发布门。

### 已完成并验证

- 16 行 Provider capability matrix 对外可见：CLI `providers`、Robot JSON、Human、Web `/api/providers` 与 MCP `list_providers`（含 deferred 行 `ingestible:false`）均从 `ProviderCapabilityMatrix::current()` 投影，并有 16 行全量漂移测试守护。
- 14 个 implemented provider 均具备结构化 `AdapterManifest`；Claude/Codex fixture revision 为 `1`，认证 target 在跨平台成功 run 前保持为空。
- Claude/Codex probe/parse source bytes read-only assertions 与真实回归 `INV-SOURCES-UNCHANGED` 已落地。
- Codex incremental resync、source-shrink tombstone、empty-source tombstone 三项合成 e2e 已落地。
- `discovery_coverage`、`resume_handoff_success` 已从 deferred 改为 measured；Windows 与 WSL2 Linux gate 均为 `pass=true`、`deferred=[]`。
- 五入口一致性 harness 全直接对比通过；`verify-release.py` 10/10；privacy scan 0 findings。
- 跨边界脱敏规则覆盖 fine-grained GitHub PAT 与嵌入 AWS secret key；MCP/Robot/Web 三入口 facet 回显与 envelope 形状一致。
- Provider rollback ADR-0010 已落地但状态仍为 `Proposed`，不得代 owner/approver 宣称 Accepted。

### 仍开放

- 最终 readiness audit verdict：`NOT_READY_EXTERNAL_BLOCKERS`——全部仓库本地 P0/P1 已闭合，剩余均为 External/owner 决定：跨平台 CI 无 named successful run（外部阻塞）、tag/Release/签名/notarization/attestation、SBOM/NOTICE/REUSE 审核签署、provider maturity 晋级（0 Beta，Claude/Codex 未 certified）、ADR/THREAT-MODEL owner 签署。
- Semantic 默认路径仍是 `bigram-hash-v1` fuzzy lexical vectorizer。可选
  `semantic-candle` feature 已落地：本地 Candle + pinned
  `intfloat-multilingual-e5-small@614241f6-candle-f32-meanpool-l2-qpass-v1`，
  通过 `asg model import --dir <bundle>` 离线导入（校验 SHA-256，永不联网）、
  `asg model status` 校验导入状态；未导入时
  semantic/hybrid 仍显式 `lexical_fallback`。默认 `cargo install` / release
  构建不启用该 feature，不得把 bigram-hash 宣传为真实语义模型。
- GitHub hosted CI 当前受外部账户级阻塞，在首步前失败；这属于 External，不得改代码伪造跨平台认证。tag/release/签名与 owner governance 由 owner 决定。


**产品名 `agent-session-grep`,CLI 别名 `asg`。**

交付采用 **CLI-first**: CLI 是个人重度用户的主入口,MCP/Robot/TUI/Web UI
通过统一 Application ADT 提供一致能力;原生 GUI 不属于首发,但保留为后续扩展边界。

把散落在 16 个 AI coding agent 本地目录里的会话历史,变成一套
**可验证、可恢复、可交接**的本地基础设施:

> 给一个模糊问题,不仅找到相关历史,还给可验证证据、关键上下文,
> 以及可直接 resume 的会话或可交给当前 agent 的 handoff pack。

- 第一用户:个人 AI coding-agent 重度用户;第二入口:agent/MCP 消费者。
- 团队同步、云端、知识图谱**不在首发范围**。
- 发布形态:一次性完整开源(发布门全绿后公开,时点是 owner 最终裁量)。
- License:MIT OR Apache-2.0 + Provider Adapter Protocol contribution policy。

## 2. 差异化主张(对已核验外部参考项目)

| 差异化 | 说明 | 对手现状 |
|---|---|---|
| Evidence-first | 每条结果带 source span 可回溯原文;handoff pack 原文/推断分栏 | 无人做到 pack 级证据契约 |
| 身份与一致性 | StableId 三级 + durable outbox + CAS generation + 失败不删除 | hstry 的 UUID v5 最接近但无 outbox |
| CJK 一等公民 | bigram 索引 + 可选 `semantic-candle` 本地 E5 后端(feature-gated、默认 off、离线导入) + 中文语义模型 benchmark 待落地后锁定(默认向量模式为 bigram-hash fuzzy-lexical,非真实语义模型) | 竞品基本无中文分词处理 |
| 诚实能力矩阵 | certified/GA/beta/experimental/unsupported 分级,证据晋级,禁止跨级宣传 | 多数项目虚标 provider 数 |
| 零遥测可验证 | 代码级禁止 + CI 静态检查 + 全局 `--offline` flag（fail-closed）+ `tests/network_egress.rs` 零 HTTP client / 唯一 loopback socket 断言 | 无人做到可验证 |
| 跨边界默认脱敏 | Web/Handoff/MCP/Robot 默认脱敏,CLI/TUI 本地不脱敏 | agentsview 有 secret 扫描但非分层边界 |
| Robot 契约 | 13+ 码 error catalog + cursor 防篡改 + retrieval_mode | cass robot 模式粒度更粗 |

## 3. 已交付的能力阶段

开源前的工程规划分十个阶段推进,实现均已落地;是否满足发布门另见 §0.1 与 §4,
本节只记录交付范围:

1. **统一发布契约**:provider-scoped identity、Robot 1.1(`retrieval_mode`)、
   能力矩阵单源、handoff-pack/v1 schema、`asg` 别名。
2. **16 provider 证据链**:证据→fixture→adapter→分级(14 实现 + 2 deferred);
   Claude/Codex 的 certified 目标尚未达成,矩阵保持 Experimental。
3. **语义/混合本地检索**:message/placement 召回 + session 聚合;lexical 永远
   可用并显式降级,默认仍是 lexical,semantic 仅在可选 feature 下启用。
4. **证据 handoff pack**:deterministic 默认、evidence/inference 分栏、
   预算/截断/脱敏、可复现。
5. **Resume metadata 与执行**:resume 命令矩阵、dry-run 默认 + opt-in 执行、
   首次强制预览。
6. **结构化活动与上下文分面**:sidechain/subagent facet、tool activity 检索、
   session metadata 搜索。
7. **Loopback Web UI parity**:`asg serve` loopback HTTP + Web UI 核心 parity +
   安全模式。
8. **离线与隐私 hook**:ADR-0009 脱敏边界、零遥测可验证、Hook 默认关闭。
9. **Benchmark、安装与开源交付物**:公开 benchmark harness、三平台安装器、
   竞品对比表(Gate D performance 复核仍 pending,见 §0.1)。
10. **最终集成与发布演练**:演练 runbook、五入口一致性 harness 与 Go/No-Go
    报告已落地;三平台干净环境演练尚未全部执行(macOS 未跑,见 §0.1)。

## 4. 发布门(全部满足才提请 owner 公开)

要点:16 provider 证据齐、Claude/Codex certified、
≥5 主流 beta/GA 主路径、semantic+benchmark、handoff-pack/v1、Web UI
parity、零遥测可验证、跨边界脱敏、Hook 默认关闭、三平台安装、
benchmark/文档/对比表一致、三平台演练通过。

## 5. 竞品事实基线(2026-08-15 精读结论,13 个外部项目)

当前仓库已保存并核验的外部参考项目为:
`ctx`、`cass`(即 `coding_agent_session_search`)、`agentsview`、`AgentRecall`、
`agent-sessions`、`agf`、`cc-switch`、`claude-historian-mcp`、`fast-resume`、
`hstry`、`memex`、`Recall`、`sessiongrep`,共 13 项。
其中 12 项可自由引用,是对比表与 benchmark 基线的合法来源;
`cass` 因其 LICENSE 含 restricted-party rider,仅限 clean-room 思路,
计入名单但不计入可引用对比基线——即”13 个外部项目”是”12 可引用 +
1 clean-room-only”。
发布前 benchmark 必须逐项给出来源、commit/version 和可复现命令;
若要继续使用”15 个外部项目”宣传口径,必须先补齐两项独立外部基线,
否则统一改称”13 个外部项目”。

- provider 覆盖:ctx 40+、agentsview 40+、AgentRecall 16、hstry 16、
  fast-resume 12、Recall 11、agent-sessions 10、agf 8、cc-switch 7、
  sessiongrep 5、memex 4、claude-historian-mcp 1、
  cass(claimed 40+,待以同一 benchmark harness 核验)。
- 检索:纯 FTS5 系(sessiongrep/agent-sessions)、FTS+模糊(fast-resume)、
  hybrid RRF(ctx/cass/Recall/agentsview/memex)、fuzzy(agf)、零存储全扫
  (claude-historian-mcp)。
- 深度精读报告(2026-08-14 生成)仅作为本地研究输入,不纳入公开树;cass 因
  clean-room 边界不产 deep-read 报告。对外可引用的结论收敛到
  `COMPETITOR-COMPARISON.md` 与本节。
- 法律红线:cass LICENSE 含 rider,仅 clean-room 思路;REUSE-LICENSE-AUDIT
  维护 direct-copy/adapt/idea-only/reject 边界。

## 6. 术语与决策日志

- 术语以 `CONTEXT.md` 为准(2026-08-15 新增决策见其日志)。
- 不可逆决策入 ADR:2026-08-15 新增 ADR-0009(跨边界输出脱敏)。
