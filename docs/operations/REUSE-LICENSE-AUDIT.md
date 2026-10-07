# 借鉴复用与许可审查报告（R0 产物）

> 治理记录（Governance Record）
>
> - decision_id: R0-REUSE-LICENSE-AUDIT
> - status: **Draft（待 approver 审阅）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0 Feasibility / Contract Gate
> - evidence_path: `docs/operations/REUSE-LICENSE-AUDIT.md`
> - approved_at: —
>
> 本报告是复用矩阵与许可判定的规范性审查记录。任何实际复用前，必须由本报告的 approver 逐项复核许可、来源坐标与 attribution 义务；fixture 边界见 `../security/FIXTURE-REDACTION-POLICY.md`，本报告不替代逐次复核。

---

## 1. 审查范围

对已调研的同类开源项目（逐项核对公开项目身份与固定 revision）的结论做许可与复用判定。判定分四级：

- **direct-copy**：许可 + 语言兼容，保留版权/NOTICE、标注修改后可直接复制到本项目 Rust 源码；
- **adapt**：设计与实现可移植，但需按本项目 Canonical/契约重写，不逐行照抄；
- **idea-only**：仅借鉴设计思想或契约形状；语言不匹配（Swift/TS）、许可存疑或有实测缺陷者降到此级；
- **reject**：许可红线、反模式或半成品，禁止复用。

> 范围更新（2026-08-29）：本报告此前写 12 项，是 cc-sessions-viewer
>（2026-08-29 加入本地镜像并精读）加入之前的快照。现在名单为 14 项。

> 范围更新（2026-10-06）：补记 Wake（公开项目 Wake，MIT，固定 commit
> `71aeca67ec80f8645d1f9d5199290c2c732036ce`，0.8.5）后名单 14→15 项，与
> `../product/COMPETITOR-COMPARISON.md` 的 15 项口径一致。Wake 本次仅登记坐标与
> 许可事实，未做资产级复用判定。

## 2. 全局硬约束（Release 阻断级）

1. **cass 与 cc-sessions-viewer 是两个法律边界,形态不同**:
   - cass 的 LICENSE 含 OpenAI/Anthropic Restricted-Party Rider,代码整体
     **reject**,只能由未读其源码者 clean-room 借鉴抽象思想。任何直接
     copy/analyze/index 其代码的行为都是许可违约;
   - cc-sessions-viewer 的 README 显示 MIT badge 但仓库内**没有 LICENSE
     文件**(GitHub 仓库元数据 `licenseInfo: null`)。没有可依赖的授权文本,
     就无法证明存在 MIT 许可——因此按**无授权**处理:不得逐字复制其代码
     (包括正则集合、SQL、前端组件),只能 clean-room 引用规范级的文档化
     设计。一旦作者补上真正的 LICENSE 文件,按新许可重新核定,并在本报告
     记录复核结果。
2. **fixtures 一律重造**:所有调研项目的 fixtures provenance 未核实,禁止复制任何真实 transcript;本项目按 `docs/security/FIXTURE-REDACTION-POLICY.md` 生成合成数据。
3. **语言边界**:本项目是全新 Rust 项目。Rust 仓(ctx / agf / Recall / hstry / memex / sessiongrep / fast-resume)代码在许可允许下可 copy/adapt;Swift/TS 仓(agent-sessions / AgentRecall / claude-historian-mcp)只能 idea-only。
4. **依赖许可单列**:任何被复用资产引入的传递依赖(如 agf 的 nucleo 系列为 MPL-2.0,须 attribution;tantivy 传递引入 ort-sys 许可不干净——已由 spike 实证)必须进 SBOM 与 `cargo deny` 白名单,未过 deny 门不得合入。
5. **制品 attribution 诚实边界**:release pipeline 生成的
   `THIRD-PARTY-DEPENDENCIES.json/.csv` 是可审计 resolved-dependency 报告,
   仅记录 `cargo metadata --locked --format-version 1` 与 `Cargo.lock` 实际
   提供的 name/version/source/lock checksum/declared license 字段;Cargo
   metadata 未声明 license 时保持 null/缺失状态,不推断 SPDX ID,不把它
   说成完整 SPDX SBOM 或最终 legal clearance,也不凭空生成固定 NOTICE/
   归属文字;每次 release bundle 仍携带该报告供 approver 复核。

## 3. 可复用项判定（经独立复核 CONFIRMED）

| 来源(许可) | 资产 | 判定 | 规范目标 | attribution |
|---|---|---|---|---|
| ctx (Apache-2.0) | WAL PRAGMA 组 + doctor integrity_check | direct-copy | Catalog 完整性控制；`../security/THREAT-MODEL.md` | 保留版权头 |
| ctx | 契约层 + additive-field 保留测试、snake→camel | adapt | `../contracts/CONTRACT-cli-robot-mcp-draft.md` | — |
| ctx | 单调 user_version 迁移 + events 去重索引 + sha256 前缀 checkpoint | adapt | Catalog 迁移与增量索引实现 | — |
| ctx | CJK bigram 分词（scriptgram） | adapt | `../adr/ADR-0001-fulltext-search-engine.md` | — |
| ctx | 只读 SQL 沙箱 raw_sql.rs | idea-only（MCP 不暴露 SQL） | `../contracts/CONTRACT-cli-robot-mcp-draft.md` §8 | — |
| agf (MIT) | bounded reader（read_head_tail/char_prefix） | idea-only | `../architecture/RFC-0002-provider-adapter-contract.md` §7；`../security/THREAT-MODEL.md` | 无上游代码落地（源码审计零命中），无 attribution 义务 |
| agf | shell quoting / PowerShell 包装 | idea-only | CLI 入口实现 | 无上游代码落地（源码审计零命中），无 attribution 义务 |
| Recall (MIT) | FTS5 external-content + 触发器 | adapt | `../adr/ADR-0001-fulltext-search-engine.md` | — |
| Recall | RRF k=60、目录子树过滤、迁移幂等骨架、JSONL roundtrip | adapt | Search、Catalog 迁移与 CLI contract 测试 | — |
| sessiongrep | 两段式检索（FTS 召回→Rust 重排） | adapt | `../adr/ADR-0001-fulltext-search-engine.md` | — |
| sessiongrep | 全 crates.io 无 vendored 供应链基线 | idea-only（模板） | 发布与供应链审计 | — |
| hstry (MIT) | 事务化 migration runner、source-scoped purge、peek bundle | adapt | Catalog 迁移与 `../contracts/CONTRACT-cli-robot-mcp-draft.md` §7 | — |
| hstry | version 单调 / outbox / retention 测试 | adapt | Catalog 一致性与 generation retention 测试 | — |
| memex (MIT) | compact 分层去重约束 UNIQUE(session_id, source_offset) | adapt | `../architecture/RFC-0001-canonical-model-and-stable-id.md` §3 | — |
| fast-resume (MIT) | 唯一 Tantivy 集成参考（有实测跨平台 bug） | idea-only | `../adr/ADR-0001-fulltext-search-engine.md` | — |
| AgentRecall (MIT, TS) | 迁移 writer 原子协议、capability registry | idea-only | Catalog migration 与 `../architecture/RFC-0002-provider-adapter-contract.md` §6 | — |
| agent-sessions (MIT, Swift) | FTS5+三触发器、索引期脱敏、语料保全测试 | idea-only | `../adr/ADR-0001-fulltext-search-engine.md`；`../security/THREAT-MODEL.md`；测试策略 | — |
| claude-historian (MIT, TS) | MCP search→at→get_session 渐进披露契约 | idea-only | `../contracts/CONTRACT-cli-robot-mcp-draft.md` §8 | 署名归属存疑，引用前澄清 |
| agentsview (Go) | SQLite 检索 UI 的 schema/查询参考 | idea-only | `../contracts/CONTRACT-cli-robot-mcp-draft.md` | 未直接复用资产，仅概念核对 |
| cass (MIT+Rider) | fail-open/staged-publish/robot-freeze 思想 | idea-only（clean-room） | Provider staging、发布与 Robot contract | 禁读源码 |
| cc-sessions-viewer (无 LICENSE 文件) | 13 类活动分类器、定价公式、CostSource 四值溯源、IME 防抖 hook、JSON 行前缀字段提取、树病态检测、parent 目录 watch 三件套、append-only rename 标题回写、meta_kind 注入分类 | idea-only（无授权文本,不逐字复制） | `crates/agent-session-grep-application/` 的 tool-activity 增强;统计/成本(未来);搜索框防抖;会话标题与注入分类(对照补强);任何树形 transcript provider 的健壮性检查;实时 watch 类功能;写路径安全样板 | 无逐字代码落地;实现均为独立编写,不引用其字符串常量、正则集合或 SQL |

## 4. 反模式登记（作为验收反例，禁止复用）

| 反模式 | 来源坐标 | 已对应守护 |
|---|---|---|
| 扫描期写上游（读操作 DELETE 上游 SQLite） | agf codex.rs prune_orphan_threads | 上游只读不变量、扫描前后 checksum、source-snapshot spike |
| 全局 session_id 主键致跨 Provider 覆盖 | agent-sessions DB.swift | `../architecture/RFC-0001-canonical-model-and-stable-id.md` |
| Provider 写入 SQL CHECK 约束致全表重建 | ctx ddl.rs + migrations.rs | Catalog schema 不把 Provider 写死为 SQL 枚举 |
| FTS 空命中回退全表扫描 | sessiongrep db.rs | `../adr/ADR-0001-fulltext-search-engine.md` 的 Search Port 边界 |
| Unix 权限位在 Windows 为 no-op 却宣称已私有化 | ctx object_store.rs | `../security/THREAT-MODEL.md` §4 Windows ACL |
| 跨入口排序不一致（bm25 ASC vs CLI DESC） | hstry db.rs vs main.rs | `../contracts/CONTRACT-cli-robot-mcp-draft.md` 的统一 Application ADT |
| 硬编码平台路径前缀 /Users | sessiongrep cursor.rs、Recall cline.rs | `../architecture/RFC-0002-provider-adapter-contract.md` §7 |
| 用户 query 直编正则/有损路径编码 | claude-historian search.ts | `../security/THREAT-MODEL.md` 输入校验控制 |
| adapter 子进程无超时/无输出上限致 OOM | hstry runner.rs、claude-historian | `../architecture/RFC-0002-provider-adapter-contract.md` §7 流式 + bounded buffer |
| mtime as i64 纳秒截断、纯 mtime 判增量 | sessiongrep、agf cache.rs | `../architecture/RFC-0001-canonical-model-and-stable-id.md` §6；source-snapshot spike |
| API key 明文入库 | AgentRecall schema.ts | `../security/THREAT-MODEL.md` §5 |
| 向量检索引入 protoc/联网模型构建依赖 | memex LanceDB、Recall candle | v1.0 不含 vector/embedding；`../adr/ADR-0002-platform-targets.md` 禁止联网构建依赖 |

## 5. spike 补充的实证结论

- **Tantivy 供应链风险已实证**：`cargo tree` 确认 tantivy 0.26.1 传递引入 `ort-sys`（ONNX Runtime），`cargo deny` 报 unlicensed。该证据从供应链维度进一步支持 `../adr/ADR-0001-fulltext-search-engine.md` 的 FTS5 默认选择（另见 `spikes/search-backend/EVIDENCE.md`、`spikes/cross-platform-packaging/EVIDENCE.md`）。

## 6. Release attribution bundle contract

The configured release workflow builds a third-party attribution bundle from the
locked resolved graph and carries both machine-readable forms in every target
archive. The JSON schema is
`agent-session-grep.third-party-dependencies/v1`; it explicitly sets
`spdx_document: false` and records why declared license values are
unverified. The CSV is a review-friendly projection of the same rows.

This closes the repository's missing release artifact surface, not the human
approval of source reuse. The bundle does not copy third-party license text,
inspect a declared `license_file`, grant a legal opinion, or replace
`cargo-deny`; any dependency whose metadata is incomplete remains an explicit
review item. The REUSE audit therefore stays `Draft` until its owner and
approver sign the direct-copy/attribution matrix.

## 7. 退出条件

- 每项拟复用资产有明确判定、来源许可、attribution 义务；
- cass clean-room 边界有可执行约束（禁止读其源码者以外的人实现）；
- cc-sessions-viewer 的授权状态有结论（作者补 LICENSE 后按新许可核定,否则一直按无授权处理）；
- 依赖传递许可进入 cargo-deny 白名单流程；
- approver 签署后本报告转 Accepted，方可在 0.1 之后按判定复用。
