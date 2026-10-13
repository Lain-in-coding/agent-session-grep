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

## 1. 审查范围与证据等级（2026-10-12 对账）

This Draft reconciles the listed historical proposals and current declarations
against product baseline `36616b7957e504aa4c6d514a50545dcd9bbc47cd` (H5).
It is not exhaustive discovery of every reuse, a full upstream comparison,
or human approval. All product line ranges below refer to H5, before this
comment-only correction. Product paths are repository-relative; upstream paths
are relative to the named P/F source at its registered reference revision.

Reuse disposition and evidence strength are separate:

- **direct-copy**: retained source bytes; permission, notices and modifications
  require asset-specific review, not an automatic authorization to copy.
- **adapt**: implementation/design adaptation, with source credit retained.
- **idea-only**: design, policy or format reference; not a blanket finding of
  independent authorship, no copied bytes, or no attribution obligations.
- **reject**: prohibited source use / negative reference, not a reusable asset.

**Historical proposal** does not prove an implementation. **Declaration-only**
records what product comments/NOTICE say. **Reference-only** records format or
policy knowledge. **Compared** is limited to A03-A06's ranges in §3.2; A04b has
only product SQL probes. Root-license metadata, original reuse provenance and
human approval are independent axes. For every current asset below,
`original_reuse_revision = not established` and `human_approval = pending`.
An observed/declared reference pin must never fill the original-revision field.
Unknown source coordinates remain `not established`, not invented.

Historical scope: the 2026-08-29 update changed the earlier 12-project snapshot
to 14 after registering cc-sessions-viewer (including an earlier source-reading
claim, not renewed authorization). The 2026-10-06 update added Wake as the
15th comparison identity and was registry-only at that time. Current G08 now
also records the already-declared Wake/Cursor format reference. F01 is a
separate Hermes format source, not a sixteenth competitor.

### 1.1 Observed root-license register

The following retained root `LICENSE` observations date to 2026-10-11/12.
They bind public source identity and exact bytes, not every subfile's license
applicability or the revision originally consulted. P05 uses the later pinned
remote-license supplement, not the rejected inherited local Git identity.

| ID | Public identity / pinned root LICENSE | Observed reference revision | Observed root license | LICENSE raw SHA256 |
|---|---|---|---|---|
| P01 | [jazzyalex/agent-sessions](https://github.com/jazzyalex/agent-sessions/blob/af4793d317ab83e73ea205ff3f91feee32a3f0dd/LICENSE) | `af4793d317ab83e73ea205ff3f91feee32a3f0dd` | MIT | `24d00fe45ab41c7304d503081dcc5ec314c91b747c683cfc9e2791940f4d9102` |
| P02 | [zszz3/AgentRecall](https://github.com/zszz3/AgentRecall/blob/3c7bfa59bc52e5fa39affabcb267dc73ae6858d2/LICENSE) | `3c7bfa59bc52e5fa39affabcb267dc73ae6858d2` | MIT | `5b7d6ac106acaf09fc7be54c32e86f8013acc20bf121301e49aa819b211ffa95` |
| P03 | [kenn-io/agentsview](https://github.com/kenn-io/agentsview/blob/a84564ad6ea35f8fb80905da4693144f89f84229/LICENSE) | `a84564ad6ea35f8fb80905da4693144f89f84229` | MIT | `ffb1006bf3c32ec8da3ad6c5f693d8516eecb355df848a694332fa13174a77d4` |
| P04 | [subinium/agf](https://github.com/subinium/agf/blob/44be9cffd3b3eeb44ff1f31a751ec8954adf14cf/LICENSE) | `44be9cffd3b3eeb44ff1f31a751ec8954adf14cf` | MIT | `26b7182e9a87bcd2c752aba2ded58aafa25f766a7f8de7460184bc0f0f53b33a` |
| P05 | [jerrywu001/cc-sessions-viewer](https://github.com/jerrywu001/cc-sessions-viewer/blob/5bf43433977189ca67e46523ae2cc845487c113e/LICENSE) | `5bf43433977189ca67e46523ae2cc845487c113e` | MIT (metadata only; old snapshot unbound) | `44c966305ba2a0f3748fd0e8c9ffd716025055ba75e621650cd231d3bc9b0d48` |
| P06 | [farion1231/cc-switch](https://github.com/farion1231/cc-switch/blob/f748f3ac4afbbbc6554a3ca2bb7e56e4036fedfa/LICENSE) | `f748f3ac4afbbbc6554a3ca2bb7e56e4036fedfa` | MIT | `912b6a597d10c43b40a0909349ed95b052b17efb6502b4898e1b35dafb896755` |
| P07 | [Vvkmnn/claude-historian-mcp](https://github.com/Vvkmnn/claude-historian-mcp/blob/b627cdfbfe46040368ed9c3f5bb2b531c65a8988/LICENSE) | `b627cdfbfe46040368ed9c3f5bb2b531c65a8988` | MIT | `bebebf9376399329855037e10f740d1f2696a1227ba098df2053d836622cca16` |
| P08 | [Dicklesworthstone/coding_agent_session_search](https://github.com/Dicklesworthstone/coding_agent_session_search/blob/aa92a45311e10a3ac9c40c3730664a7366af2fe8/LICENSE) | `aa92a45311e10a3ac9c40c3730664a7366af2fe8` | MIT text + restricted-party rider | `32a82e0a5754e72e51fae44b65a936c831c07376f21c90f5fb9e76897fcc3509` |
| P09 | [ctxrs/ctx](https://github.com/ctxrs/ctx/blob/06bc5ed17ce4d0f6c8255981e009f86802dbe32f/LICENSE) | `06bc5ed17ce4d0f6c8255981e009f86802dbe32f` | Apache-2.0 | `c1b9df1275e769f3dbab000d1e457a2d4b0f28eb5da6c77e48dc37eeba202ed7` |
| P10 | [angristan/fast-resume](https://github.com/angristan/fast-resume/blob/66e42cfd34bca4800161098d3b302a35a52ce69b/LICENSE) | `66e42cfd34bca4800161098d3b302a35a52ce69b` | MIT | `a76330d5de8374ae5aebe49c04c3e4b9fe2512623e7b60ab79b540fbd6988e4c` |
| P11 | [byteowlz/hstry](https://github.com/byteowlz/hstry/blob/88b78b1f3a84723e31a2c444bec326829fd02459/LICENSE) | `88b78b1f3a84723e31a2c444bec326829fd02459` | MIT | `647221b987aeb9a07979d10ff7ca51dea253d3baca226aee75838f7f72b72bf1` |
| P12 | [vimo-ai/memex](https://github.com/vimo-ai/memex/blob/9a88a5cbeccd14ef2a526729e1815b8df0793414/LICENSE) | `9a88a5cbeccd14ef2a526729e1815b8df0793414` | MIT | `94711e73977c87991f1e6e3deec5e7f25fa06a113ae2b9638d929e291ace2d40` |
| P13 | [samzong/Recall](https://github.com/samzong/Recall/blob/22625bf8979a185d9913c1bfb20290ac466d492b/LICENSE) | `22625bf8979a185d9913c1bfb20290ac466d492b` | MIT | `6f33b8ae9f6338c09adf50d21c15812931524048c7f192a6620470808a7e4125` |
| P14 | [braincompany/sessiongrep](https://github.com/braincompany/sessiongrep/blob/c5c1874f420fb20cc55e484f79bdff3d848b71a8/LICENSE) | `c5c1874f420fb20cc55e484f79bdff3d848b71a8` | Apache-2.0 | `871d95d5ab3ca6374d016410e7ec0984a3bca83a1002225061fde3b417b47f52` |
| P15 | [iAmCorey/Wake](https://github.com/iAmCorey/Wake/blob/71aeca67ec80f8645d1f9d5199290c2c732036ce/LICENSE) | `71aeca67ec80f8645d1f9d5199290c2c732036ce` | MIT | `f55cdc249d70963038f7c17973d0a16c58a490912da7404274f0dfaddbdc7cf2` |

P05 is repository ID `1244579680`. Its LICENSE was added at
`91337d151fb93290fa802cf90be1f52e11e1b62e` (2026-09-16); the observed license
blob is `a29418dd0cb1d6301f0c6f7e86d3ff29ca5af5d3`, declaring
`Copyright (c) 2026 jerrywu001`. The old unversioned local snapshot has no
independent Git root: the inherited ancestor development checkout Git identity
and `f587c73332158342330a63874fabdc8f565624ec` are **rejected** as evidence of its
provenance. Current MIT metadata neither binds nor retroactively authorizes that
snapshot. No source read/copy is authorized by this correction.

### 1.2 Additional declared format source

| ID | Identity | Declared reference revision / asset | License and provenance status |
|---|---|---|---|
| F01 | NousResearch/hermes-agent | `bac0c45d8593ed9d53a8e3fcacecdc920b71a2c4`; [hermes_state_common.py](https://github.com/NousResearch/hermes-agent/blob/bac0c45d8593ed9d53a8e3fcacecdc920b71a2c4/hermes_state_common.py), declared blob `e35e61a06a3c69ebea6b37accec72d10cead20dc` | Root-license receipt and applicability **not established**; original reuse revision unknown; approval pending |

F01 is declared by `crates/agent-session-grep-provider-hermes/src/lib.rs:21-25`
and its `crates/agent-session-grep-provider-hermes/tests/golden/PROVENANCE.md:105-112` (schema30 columns/tool-call
envelopes). Their no-copied-bytes/synthetic-fixture statements remain product
declarations, not independent findings here. Do not apply P11 hstry's MIT
license to F01. No new upstream source or fixture was read for this correction.

## 2. 全局硬约束（Release 阻断级）

1. **Restricted sources remain restricted**:
   - P08 cass has an OpenAI/Anthropic Restricted-Party Rider. Source use is
     **reject**: do not read, analyze, index or copy its source. Preserve only
     existing abstract/negative references; earlier reports do not establish
     a clean-room chain or permission to read. This is the current project
     boundary, not a new legal opinion about every use.
   - P05 cc-sessions-viewer's earlier no-LICENSE / `licenseInfo: null`
     observation is historical. §1.1 records current pinned MIT metadata;
     historical provenance remains unresolved. Do not read/copy its source,
     regex sets, SQL or fixtures in this work. G10's existing named patterns
     require provenance review; neither copying nor independence is proved.
2. **fixtures 一律重造**:所有调研项目的 fixtures provenance 未核实,禁止复制任何真实 transcript;本项目按 `docs/security/FIXTURE-REDACTION-POLICY.md` 生成合成数据。
3. **语言与复用政策分开**: Rust compatibility does not prove copying or permission;
   cross-language implementation can still be an adaptation (A03). Preserve
   the existing idea-only scope for Swift/TS references and restricted-source
   boundaries. Classification follows the particular asset and evidence, not
   repository language; this correction grants no new source-use scope.
4. **依赖许可单列（2026-10-12 更正）**: Review dependencies actually introduced
   into the resolved graph under the existing cargo-deny policy; do not inherit
   an upstream dependency merely from idea reuse (including the earlier agf/
   nucleo example). The committed spike lock does not support the asserted
   Tantivy → ort-sys failure (§5). Keep metadata gaps explicit, require real
   command/source-bound license evidence, and do not broaden allowlists or
   claim a complete SBOM/license pass from this correction.
5. **制品 attribution 诚实边界**:release pipeline 生成的
   `THIRD-PARTY-DEPENDENCIES.json/.csv` 是可审计 resolved-dependency 报告,
   仅记录 `cargo metadata --locked --format-version 1` 与 `Cargo.lock` 实际
   提供的 name/version/source/lock checksum/declared license 字段;Cargo
   metadata 未声明 license 时保持 null/缺失状态,不推断 SPDX ID,不把它
   说成完整 SPDX SBOM 或最终 legal clearance,也不凭空生成固定 NOTICE/
   归属文字;每次 release bundle 仍携带该报告供 approver 复核。

## 3. Asset dispositions — historical proposals and current evidence

### 3.1 Historical audit rows (S01-S21)

All original subitems and normative targets are retained. A proposal without a
current binding is not asserted absent from the product, implemented, approved,
or exempt from notice obligations. Original consultation revisions are not
established; human approval remains pending. Product paths in §3 are
repository-relative. Upstream links use the registered reference pins;
outside the compared ranges they preserve declared coordinates, not newly
verified file existence at that snapshot or original consultation revisions.

| ID | Source | Asset(s) | Disposition / evidence | Original normative target | Attribution / remaining limit |
|---|---|---|---|---|---|
| S01 | ctx (Apache-2.0) | WAL PRAGMA 组 + doctor integrity_check | adapt (WAL); idea-only (doctor) | Catalog 完整性控制；`../security/THREAT-MODEL.md` | A04a compares only WAL/cache; A04b only SQL probes, no copied doctor function established; ctx notice observations in §3.2. |
| S02 | ctx | 契约层 + additive-field 保留测试、snake→camel | adapt proposal | `../contracts/CONTRACT-cli-robot-mcp-draft.md` | Three proposals retained separately: contract layer; additive-field retention tests; snake→camel. Product/source binding not established. |
| S03 | ctx | 单调 user_version 迁移 + events 去重索引 + sha256 前缀 checkpoint | adapt proposal | Catalog 迁移与增量索引实现 | Three proposals retained: monotonic user_version; events dedup index; sha256-prefix checkpoint. Binding not established; not a blanket attribution of local migrations. |
| S04 | ctx | CJK bigram 分词（scriptgram） | adapt declaration | `../adr/ADR-0001-fulltext-search-engine.md` | N01b current declaration, not newly source-compared; preserve ctx credit. |
| S05 | ctx | 只读 SQL 沙箱 raw_sql.rs | idea-only proposal (MCP 不暴露 SQL) | `../contracts/CONTRACT-cli-robot-mcp-draft.md` §8 | Historical raw_sql.rs reference only; implementation binding not established; no SQL API added. |
| S06 | agf (MIT) | bounded reader（read_head_tail/char_prefix） | idea-only (A05b) | `../architecture/RFC-0002-provider-adapter-contract.md` §7；`../security/THREAT-MODEL.md` | Local bounded line/stream implementation differs from reference head/tail reader; differences do not prove independent authorship. Credit retained; no blanket obligation waiver. |
| S07 | agf | shell quoting / PowerShell 包装 | adapt (POSIX, A05a); PowerShell unestablished | CLI 入口实现 | POSIX similarity plus local safe-token passthrough; PowerShell code reuse not established. Conservative agf MIT notice in NOTICE. |
| S08 | Recall (MIT) | FTS5 external-content + 触发器 | adapt proposal | `../adr/ADR-0001-fulltext-search-engine.md` | Historical FTS/trigger proposal remains unbound; N04 activity/embedding are different assets. |
| S09 | Recall | Recall RRF historical reference; 目录子树过滤; 迁移幂等骨架; JSONL roundtrip | historical adapt proposal; current RRF → P09 | Search、Catalog 迁移与 CLI contract 测试 | (1) Recall RRF historical reference retained without a newly verified upstream k value; current k=60 declaration is ctx/N01c. (2) subtree filtering, (3) idempotent migrations, (4) JSONL roundtrip remain separate unbound proposals. |
| S10 | sessiongrep (P14, Apache-2.0) | 两段式检索（FTS 召回→Rust 重排） | adapt declaration | `../adr/ADR-0001-fulltext-search-engine.md` | N03 / application/src/ranking.rs:7-9; observed Apache-2.0, original revision unknown. |
| S11 | sessiongrep | 全 crates.io 无 vendored 供应链基线 | idea-only design reference | 发布与供应链审计 | Policy reference only, not an inherited supply-chain pass or local dependency inventory. |
| S12 | hstry (MIT) | 事务化 migration runner、source-scoped purge、peek bundle | migration adapt declaration; peek idea; purge proposal | Catalog 迁移与 `../contracts/CONTRACT-cli-robot-mcp-draft.md` §7 | (1) migration runner → N06b; (2) source-scoped purge binding not established; (3) peek → application/src/peek.rs:4,17 and cli/src/mcp.rs:2531 (idea-only declaration). Provider formats are separate. |
| S13 | hstry | version 单调 / outbox / retention 测试 | adapt proposal | Catalog 一致性与 generation retention 测试 | Version monotonicity, outbox tests and retention tests remain three unbound proposals; no new upstream outbox claim or copied tests. |
| S14 | memex (MIT) | compact 分层去重约束 UNIQUE(session_id, source_offset) | adapt declaration | `../architecture/RFC-0001-canonical-model-and-stable-id.md` §3 | N07: declared adaptation from two-column constraint to placement UNIQUE(session_id, document_id, source_ordinal); original source binding unknown. |
| S15 | fast-resume (MIT) | 唯一 Tantivy 集成参考（有实测跨平台 bug） | idea-only historical reference | `../adr/ADR-0001-fulltext-search-engine.md` | Historical Tantivy reference/defect assessment not reverified; N05 health and four providers are distinct declared adaptations. |
| S16 | AgentRecall (MIT, TS) | 迁移 writer 原子协议、capability registry | idea-only proposals | Catalog migration 与 `../architecture/RFC-0002-provider-adapter-contract.md` §6 | Writer atomic protocol and capability registry remain two unbound proposals; CodeBuddy and ranking references are distinct (N10a/G01). |
| S17 | agent-sessions (MIT, Swift) | FTS5+三触发器、索引期脱敏、语料保全测试 | idea-only proposals / redaction declaration | `../adr/ADR-0001-fulltext-search-engine.md`；`../security/THREAT-MODEL.md`；测试策略 | (1) FTS5/three triggers and (3) corpus-preservation tests remain unbound proposals; (2) index-time redaction has distinct P01 credit N10b, product location not established. |
| S18 | claude-historian (MIT, TS) | MCP search→at→get_session 渐进披露契约 | idea-only historical proposal | `../contracts/CONTRACT-cli-robot-mcp-draft.md` §8 | Progressive disclosure remains a separate proposal; declared MIT copyright is not independent ownership proof. A06 prefilters are a different asset. |
| S19 | agentsview (Go) | SQLite 检索 UI 的 schema/查询参考 | idea-only historical proposal | `../contracts/CONTRACT-cli-robot-mcp-draft.md` | Historical schema/UI concept-only statement applies to this asset, not the whole project; A03/N08 is implemented Aider adaptation. |
| S20 | cass (MIT+Rider) | fail-open/staged-publish/robot-freeze 思想 | idea-only abstract reference; code reject | Provider staging、发布与 Robot contract | Restricted negative/idea references only; no source read/analyze/index/copy or clean-room certification. |
| S21 | cc-sessions-viewer (P05; old unlicensed snapshot / current MIT metadata) | 13 类活动分类器、定价公式、CostSource 四值溯源、IME 防抖 hook、JSON 行前缀字段提取、树病态检测、parent 目录 watch 三件套、append-only rename 标题回写、meta_kind 注入分类 | idea-only historical proposals; unresolved declarations | `crates/agent-session-grep-application/` 的 tool-activity 增强;统计/成本(未来);搜索框防抖;会话标题与注入分类(对照补强);任何树形 transcript provider 的健壮性检查;实时 watch 类功能;写路径安全样板 | All nine listed groups retained as historical proposals, not proven implementations. Current MIT metadata is separate from the old unlicensed snapshot. G10 names patterns but proves neither copied regex bytes nor independent authorship; provenance unresolved. |

### 3.2 Bounded compared assets (A03-A06)

Only the following ranges inherit the retained comparison. Entire-file hashes
are bindings, not full-file review. P IDs resolve the exact public reference
revision, root license and license hash in §1.1. Each asset retains credit in
NOTICE; original consultation revision is **not established**, and approval
is **pending**. The A05 differences do not establish independent authorship.

| Asset / cross-reference | Product path and H5 lines | Source path and compared reference lines | Disposition and observed difference | Notice disposition |
|---|---|---|---|---|
| A03 / N08 | `crates/agent-session-grep-provider-aider/src/lib.rs:1-25,180-262,300-327` | P03 [internal/parser/aider.go:276-365](https://github.com/kenn-io/agentsview/blob/a84564ad6ea35f8fb80905da4693144f89f84229/internal/parser/aider.go#L276-L365) | adapt; line-prefix/channel-state reconstruction, different local run handling and tool-output folding | Preserve agentsview credit; full observed MIT text in NOTICE |
| A04a / S01,N01a | `crates/agent-session-grep-adapters-sqlite/src/lib.rs:1797-1824` | P09 [crates/ctx-history-store/src/connection.rs:218-230](https://github.com/ctxrs/ctx/blob/06bc5ed17ce4d0f6c8255981e009f86802dbe32f/crates/ctx-history-store/src/connection.rs#L218-L230) | bounded adapt/configuration reference; shared WAL literal, different PRAGMA set/cache value; not a complete copied initialization | Preserve ctx/Apache credit; no invented copyright holder |
| A04b / S01 | `crates/agent-session-grep-adapters-sqlite/src/maintenance.rs:778`; `crates/agent-session-grep-adapters-sqlite/src/relocation.rs:1727` | P09 same [connection.rs:192-208](https://github.com/ctxrs/ctx/blob/06bc5ed17ce4d0f6c8255981e009f86802dbe32f/crates/ctx-history-store/src/connection.rs#L192-L208) | idea-only integrity/quick-check; product SQL literal probes only, not a comparison of whole doctor functions or proof of copying validate | Separate idea credit retained; cannot inherit A04a comparison |
| A05a / S07,N02a | `crates/agent-session-grep-application/src/guidance.rs:116-140` | P04 [src/shell.rs:64-93](https://github.com/subinium/agf/blob/44be9cffd3b3eeb44ff1f31a751ec8954adf14cf/src/shell.rs#L64-L93) | conservative adapt; similar POSIX quoting with local safe-token passthrough; PowerShell copying not established | Full observed agf MIT text in NOTICE |
| A05b / S06,N02b | `crates/agent-session-grep-ports/src/lib.rs:1446-1550` | P04 [src/scanner/mod.rs:47-50,107-174](https://github.com/subinium/agf/blob/44be9cffd3b3eeb44ff1f31a751ec8954adf14cf/src/scanner/mod.rs) | idea-only; local bounded line/stream limits and buffering differ from the head/tail reader | Retain agf idea credit; remove blanket no-code/no-obligation finding |
| A06 / N09 | `crates/agent-session-grep-provider-claude/src/lib.rs:46-55,160-181,916-929`; `crates/agent-session-grep-provider-codex/src/lib.rs:58-65,164-177,879-893` | P07 [src/parser.ts:55-176](https://github.com/Vvkmnn/claude-historian-mcp/blob/b627cdfbfe46040368ed9c3f5bb2b531c65a8988/src/parser.ts#L55-L176) | idea-only prefilter-before-parse; upstream query-substring rejection differs from local envelope markers; unknown/ambiguous records parse | Retain both entry-point credits and declared MIT copyright; distinct from S18 |

Source-file bindings at those P revisions (not proofs of original reuse):

| Source | Git blob | Raw SHA256 |
|---|---|---|
| P03 [internal/parser/aider.go](https://github.com/kenn-io/agentsview/blob/a84564ad6ea35f8fb80905da4693144f89f84229/internal/parser/aider.go) | `761c07e73eb4c8fb79358a7a97dbb91fd047a272` | `31dc06df0fa88eba9d92b10d7afabfc9c1c79d166265ef43c3e969c475fcbbca` |
| P09 [crates/ctx-history-store/src/connection.rs](https://github.com/ctxrs/ctx/blob/06bc5ed17ce4d0f6c8255981e009f86802dbe32f/crates/ctx-history-store/src/connection.rs) | `14bfcea8997e1f66423a55c4d399ac7a301041d5` | `519439f0262a948ca74af230ce6505cd5263dc8710754b026d7166e7eb6cf3f6` |
| P04 [src/shell.rs](https://github.com/subinium/agf/blob/44be9cffd3b3eeb44ff1f31a751ec8954adf14cf/src/shell.rs) | `7edf733c247dbc2cf997dbbd8d4d5213eae73cb3` | `bd2d0d46efac9bfa52f2a777a2a5906b6001ce6361cb532900805ca5fce0239e` |
| P04 [src/scanner/mod.rs](https://github.com/subinium/agf/blob/44be9cffd3b3eeb44ff1f31a751ec8954adf14cf/src/scanner/mod.rs) | `afd65a55fed9fd4d586db072762297cb57e165cb` | `e713486c581b3b506bdd8048273e874788378cc087b831dcf034b42a4c14fc2f` |
| P07 [src/parser.ts](https://github.com/Vvkmnn/claude-historian-mcp/blob/b627cdfbfe46040368ed9c3f5bb2b531c65a8988/src/parser.ts) | `6ac09f2d52fd896e2081f92cd4a673a6a947cc8b` | `35f60ff831881543d063b0f8e417cf16a948c7e1a24a13bf6aef702a3fdd4968` |

The observed P09 root has no NOTICE; the compared connection source has no
copyright header. `Copyright [yyyy] [name of copyright owner]` in the Apache
appendix is a template, not a holder. P14's root declares
`Copyright 2026 Brain Co. Technologies Inc.`; P07's MIT root declares
`Copyright (c) 2025 Claude Code Community`, not independently proved ownership.

Old-product declaration-introduction commits: ctx/agf
`c451e67a4f0de2df6a34810056767a6556137f1e`, prefilters
`7d3107b34110662587aee226793827e81d59b9c8`, Aider
`6470d766c33c506656cae57ca76764372623c49d`. These date declarations, not original
upstream consultation. Shallow reference history cannot prove a historical
implementation/license never existed.

### 3.3 Current NOTICE assets (N01-N11)

Outside the A rows, comparison status is **declaration-only** or
**reference-only**, not independently compared. All P assets inherit the
observed root metadata in §1.1, retain source credit in NOTICE, have unknown
original revisions, and await human approval. Unspecified source path/range
or product location is **not established**. Conservative full MIT notices for
P03/P04/P10/P11/P12/P13 do not settle historical authorization or substantiality.

| ID | Source and asset | Product declaration / H5 location | Category and evidence / remaining limit |
|---|---|---|---|
| N01a | P09 WAL/cache | `crates/agent-session-grep-adapters-sqlite/src/lib.rs:1814-1824` | adapt; A04a |
| N01b | P09 CJK bigram (scriptgram) | root `NOTICE` CJK declaration; current transform `crates/agent-session-grep-application/src/cjk.rs:1-12` | adapt, declaration-only; source range not established |
| N01c | P09 weighted RRF k=60, declared [src/search.rs](https://github.com/ctxrs/ctx/blob/06bc5ed17ce4d0f6c8255981e009f86802dbe32f/src/search.rs) | `crates/agent-session-grep-application/src/hybrid.rs:6-13` | adapt declaration; reconcile S09 to ctx, no newly verified Recall k value or exclusive ownership claim |
| N02a / N02b | P04 POSIX quoting / bounded reading | A05a / A05b | conservative adapt / idea-only, separately credited |
| N03 | P14 FTS bm25 candidate retrieval → Rust rerank | `crates/agent-session-grep-application/src/ranking.rs:7-9`; root `NOTICE` | adapt declaration, observed Apache metadata; G01 ranking signal separately referenced |
| N04a | P13 activity target priority chain, declared `events.rs` | `crates/agent-session-grep-application/src/activity.rs:8-9,166`; `crates/agent-session-grep-ports/src/lib.rs:631-635` | adapt declaration; not S08 FTS triggers |
| N04b | P13 Candle E5 architecture, declared [src/embedding.rs](https://github.com/samzong/Recall/blob/22625bf8979a185d9913c1bfb20290ac466d492b/src/embedding.rs) (BertModel, mean pooling, L2, query:/passage:) | `crates/agent-session-grep-application/src/candle_embedding.rs:11-13` | adapt declaration; local download path absent; model weights are M01, not this source asset |
| N05a | P10 jsonl_health, declared [src/adapters/shared.rs](https://github.com/angristan/fast-resume/blob/66e42cfd34bca4800161098d3b302a35a52ce69b/src/adapters/shared.rs) | `crates/agent-session-grep-cli/src/lib.rs:4824-4825` | adapt declaration; retained source copyright (Stanislas Lange) |
| N05b | P10 OpenCode schema queries, declared [src/adapters/opencode.rs](https://github.com/angristan/fast-resume/blob/66e42cfd34bca4800161098d3b302a35a52ce69b/src/adapters/opencode.rs) | `crates/agent-session-grep-provider-opencode/src/lib.rs:8-9` | adapt declaration |
| N05c | P10 Pi extraction, declared [src/adapters/pi.rs](https://github.com/angristan/fast-resume/blob/66e42cfd34bca4800161098d3b302a35a52ce69b/src/adapters/pi.rs) | `crates/agent-session-grep-provider-pi/src/lib.rs:10-11` | adapt declaration; indirect OpenClaw chain in G05 |
| N05d | P10 Grok extraction, declared [src/adapters/grok.rs](https://github.com/angristan/fast-resume/blob/66e42cfd34bca4800161098d3b302a35a52ce69b/src/adapters/grok.rs) | `crates/agent-session-grep-provider-grok/src/lib.rs:12-13` | adapt declaration |
| N05e | P10 Kimi extraction, declared [src/adapters/kimi.rs](https://github.com/angristan/fast-resume/blob/66e42cfd34bca4800161098d3b302a35a52ce69b/src/adapters/kimi.rs) | `crates/agent-session-grep-provider-kimi/src/lib.rs:9-10` | adapt declaration |
| N06a | P11 Hermes JSON/per-message extraction, declared [adapters/hermes/adapter.ts](https://github.com/byteowlz/hstry/blob/88b78b1f3a84723e31a2c444bec326829fd02459/adapters/hermes/adapter.ts) @ P11 pin | `crates/agent-session-grep-provider-hermes/src/lib.rs:21-25` | adapt declaration; not F01 SQLite schema30 |
| N06b | P11 transactional migration runner concepts | root `NOTICE`; precise migration source/product range not established | adapt declaration; distinct from S12 purge/peek and G04 |
| N07 | P12 layered dedup constraint, two columns → `UNIQUE(session_id, document_id, source_ordinal)` | root `NOTICE` placement-constraint declaration; precise range not established | adapt declaration; transformation is not a full provenance proof |
| N08 | P03 Aider channel-state parsing | A03 | compared adapt, separate from S19 schema/UI |
| N09 | P07 Claude and Codex prefilters | A06 | compared idea-only, separate from S18 progressive disclosure |
| N10a | P02 CodeBuddy format/root-message filter (`codebuddy-cli` reference) | `crates/agent-session-grep-provider-codebuddy/src/lib.rs:13-16` | idea-only declaration; not P01 redaction |
| N10b | P01 index-time redaction | root `NOTICE`; product/source implementation location not established | idea-only declaration; distinct identity retained, not inferred copied Swift code |
| N11 | Contributor Covenant v2.1, CC BY 4.0 text | root `CODE_OF_CONDUCT.md:127-145` | adapted text; preserve version, source, license, Mozilla inspiration and local additions; not a competitor; source-text approval not granted here |

### 3.4 Additional current declarations / format references (G01-G12)

Each row below is **declaration-only** or **reference-only**, not a new source
comparison. Original reuse revision remains unknown, human approval pending;
P IDs provide observed metadata only. Unless a declared source path is stated,
that path/range is not established. Credit is retained in this inventory and
NOTICE's reference section; a text occurrence alone neither adds a proved
copied asset nor removes an obligation. H5 line anchors are navigation only.

| ID | Source / referenced subitems | Product H5 anchors (repository-relative) | Disposition / notice limit |
|---|---|---|---|
| G01 | P02 smartScore half-life; P14 current-repo boost/retrieval; P03 sidechain rank penalty | `crates/agent-session-grep-application/src/ranking.rs:5-10` | Three idea/reference subitems, local score scaling; preserve all credits, not A03 source comparison |
| G02 | P09 policy grading; retention length; Qoder/Cline format support matrix | `crates/agent-session-grep-application/src/activity.rs:8`, `retention.rs:3`; `crates/agent-session-grep-provider-qoder/src/lib.rs:10`; `crates/agent-session-grep-provider-cline/src/lib.rs:7` | Separate policy/format references; do not inherit WAL evidence |
| G03 | P13 incremental parser_version; P13/P14 repository identity; P13 usage shape | `crates/agent-session-grep-adapters-sqlite/src/lib.rs:2402,4594,8734,8817-8818`; `crates/agent-session-grep-cli/src/repo_identity.rs:4-9`; `crates/agent-session-grep-provider-claude/src/lib.rs:544,2708`; `crates/agent-session-grep-provider-codex/src/lib.rs:54,389-540`; `crates/agent-session-grep-ports/src/capability.rs:622` | Three strategy/shape reference groups; URL examples are not copied-fixture proof |
| G04 | P11 bulk insert ([crates/hstry-core/src/db.rs](https://github.com/byteowlz/hstry/blob/88b78b1f3a84723e31a2c444bec326829fd02459/crates/hstry-core/src/db.rs) declaration); query sanitization; fork_type; Cursor ItemTable | `crates/agent-session-grep-adapters-sqlite/src/lib.rs:109-113,6932,7025,7642-7643,10176,11411`; `crates/agent-session-grep-cli/src/lib.rs:4455,6531`; `crates/agent-session-grep-provider-cursor/src/lib.rs:22-28` | Preserve each declaration/reference; not all migration assets; Cursor shape/no-copy claim remains a declaration |
| G05 | P10 through local Pi → OpenClaw; resume; health/failure scan | `crates/agent-session-grep-provider-openclaw/src/lib.rs:13-17`; `crates/agent-session-grep-application/src/resume.rs:94,102,119`; `crates/agent-session-grep-adapters-sqlite/src/lib.rs:4208`; `crates/agent-session-grep-cli/src/lib.rs:4884,5092` | Indirect declared reuse chain plus resume/health references; no claim of direct upstream OpenClaw copying |
| G06 | P03 unknown-vs-zero policy; forwarding-header idea | `crates/agent-session-grep-ports/src/lib.rs:195`; `crates/agent-session-grep-domain/src/lib.rs:338`; `crates/agent-session-grep-adapters-sqlite/src/lib.rs:2926`; `crates/agent-session-grep-cli/src/serve.rs:349` | Two policy/idea groups, distinct from Aider; full MIT preservation is not proof of code reuse here |
| G07 | P06 resume/format positive and negative references | `crates/agent-session-grep-application/src/resume.rs:122,137,453,524`; `crates/agent-session-grep-ports/src/capability.rs:406,549`; `crates/agent-session-grep-provider-claude/src/lib.rs:605` | idea/format reference; keep unknown/unavailable resume capability, no newly established adaptation |
| G08 | P15 Wake Cursor format: declared [crates/wake-core/src/adapters/cursor_ide.rs:189-236,346-384,458-545](https://github.com/iAmCorey/Wake/blob/71aeca67ec80f8645d1f9d5199290c2c732036ce/crates/wake-core/src/adapters/cursor_ide.rs) at P15 pin | `crates/agent-session-grep-provider-cursor/src/disk_kv.rs:45-48`; `crates/agent-session-grep-provider-cursor/src/lib.rs:27-28`; `crates/agent-session-grep-provider-cursor/tests/golden/PROVENANCE.md:109-124` in that provider | reference-only; declared structural facts/synthetic/no-copied-bytes, not newly proved copying, independence or shipped-version compatibility |
| G09 | P11 Hermes JSON versus F01 official schema30 SQLite columns and tool-call envelopes | `crates/agent-session-grep-provider-hermes/src/lib.rs:21-25`; its `crates/agent-session-grep-provider-hermes/tests/golden/PROVENANCE.md:105-112` | Distinct sources/variants; F01 applicability unknown, not P11 MIT; source comment's broad license wording is not a verified license finding |
| G10 | P05 named INTERRUPT_RE / format.ts envelopes / claude.rs image shape alongside P02/P14/P06 | `crates/agent-session-grep-provider-claude/src/lib.rs:597-619` | unresolved pattern provenance; named references prove neither copied regex bytes nor independence. Current MIT metadata does not resolve old provenance; no restricted source read/copy |
| G11 | P10 fixture-name references; P13 repository URL examples | `crates/agent-session-grep-provider-pi/src/lib.rs:436-439`; `crates/agent-session-grep-provider-grok/src/lib.rs:404,567`; `crates/agent-session-grep-cli/src/repo_identity.rs:465-487` | Navigation/provenance limits, not extra proved copied assets. No upstream fixtures or real transcripts used to fill gaps |
| G12 | P11/P12 release-profile comparisons; P07 negative ranking reference | root `Cargo.toml:28-45`; `crates/agent-session-grep-application/src/ranking.rs:12` | Historical selection/negative references; no default bundled-code, new benchmark or performance claim |

Cross-record corrections: **C01** reconciles ctx/sessiongrep Apache metadata;
**C02** separates current P05 MIT from the old snapshot and rejected identity;
**C03** preserves cass's no-read/analyze/index/copy boundary; **C04** maps current
RRF to ctx while retaining Recall history; **C05** splits AgentRecall and
agent-sessions; **C06** dates the old no-semantic scope (X12 / ADR-0001);
**C07** corrects the unsupported dependency chain and downstream reasoning
(§5 / both ADRs / dated spike appendices); **C08** separates categories,
language, evidence and approval.

## 4. 反模式登记（作为验收反例，禁止复用）

All X01-X12 remain **negative-reference / guard-not-reverified**. Existing
guard mappings are preserved, not re-tested upstream claims or code reuse.

| ID | 反模式 | 来源坐标 | 已对应守护 |
|---|---|---|---|
| X01 | 扫描期写上游（读操作 DELETE 上游 SQLite） | agf codex.rs prune_orphan_threads | 上游只读不变量、扫描前后 checksum、source-snapshot spike |
| X02 | 全局 session_id 主键致跨 Provider 覆盖 | agent-sessions DB.swift | `../architecture/RFC-0001-canonical-model-and-stable-id.md` |
| X03 | Provider 写入 SQL CHECK 约束致全表重建 | ctx ddl.rs + migrations.rs | Catalog schema 不把 Provider 写死为 SQL 枚举 |
| X04 | FTS 空命中回退全表扫描 | sessiongrep db.rs | `../adr/ADR-0001-fulltext-search-engine.md` 的 Search Port 边界 |
| X05 | Unix 权限位在 Windows 为 no-op 却宣称已私有化 | ctx object_store.rs | `../security/THREAT-MODEL.md` §4 Windows ACL |
| X06 | 跨入口排序不一致（bm25 ASC vs CLI DESC） | hstry db.rs vs main.rs | `../contracts/CONTRACT-cli-robot-mcp-draft.md` 的统一 Application ADT |
| X07 | 硬编码平台路径前缀 /Users | sessiongrep cursor.rs、Recall cline.rs | `../architecture/RFC-0002-provider-adapter-contract.md` §7 |
| X08 | 用户 query 直编正则/有损路径编码 | claude-historian search.ts | `../security/THREAT-MODEL.md` 输入校验控制 |
| X09 | adapter 子进程无超时/无输出上限致 OOM | hstry runner.rs、claude-historian | `../architecture/RFC-0002-provider-adapter-contract.md` §7 流式 + bounded buffer |
| X10 | mtime as i64 纳秒截断、纯 mtime 判增量 | sessiongrep、agf cache.rs | `../architecture/RFC-0001-canonical-model-and-stable-id.md` §6；source-snapshot spike |
| X11 | API key 明文入库 | AgentRecall schema.ts | `../security/THREAT-MODEL.md` §5 |
| X12 | 向量检索引入 protoc/联网模型构建依赖 | memex LanceDB、Recall candle | 历史 R0 范围曾为 v1.0 不含 vector/embedding；2026-10-12 澄清：当前默认 lexical，opt-in semantic-candle + 离线本地导入；`../adr/ADR-0002-platform-targets.md` 禁止联网构建依赖仍有效，权重分发/晋级未获本次批准 |

## 5. Spike dependency-evidence correction (2026-10-12)

The earlier claim that Tantivy 0.26.1 transitively introduced `ort-sys` and
produced a cargo-deny `unlicensed` failure is **not substantiated by the
committed evidence**. H5's `spikes/search-backend/Cargo.lock` has raw SHA256
`77e547af8ff41e17429f334b13607a5bf7829ed7e04f7cbdb511352b8f1aa41d`:
151 locked packages, 140 in the recorded Tantivy closure, no `ort-sys`
anywhere in that lock and no path to it. This observation is confined to that
source/lock, not every Tantivy version or historical environment.

The [packaging probe](../../spikes/cross-platform-packaging/verify-release-pipeline.ps1)
step 2 invokes `cargo audit`, **not cargo-deny**; its old fixed INFO string
was not an executed license check. Historical failure reproduction requires
the exact source, lock/configuration, command, tool version and result; those
inputs remain unestablished. Absence from this graph is neither a new
cargo-deny pass nor proof that the event never happened.

The original claims and measured results remain in
[the R0 summary](../../spikes/R0-EVIDENCE-SUMMARY.md) and
[packaging evidence](../../spikes/cross-platform-packaging/EVIDENCE.md), each
with an appended dated correction. Do not use the old dependency claim or
its inferred ctx-fork/cleaner-FTS5 rationale as decision evidence.
[Search-backend measurements](../../spikes/search-backend/EVIDENCE.md) still
support the bounded recall comparison and single-storage consistency rationale
in [ADR-0001](../adr/ADR-0001-fulltext-search-engine.md), with scale/platform/
ranking limits intact. The FTS5 default, dependencies and approval status do
not change; neither backend receives universal license clearance.

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
- cass 源码禁止 read/analyze/index/copy；仅保留已有抽象/反例引用，不把历史报告或本次对账视为 clean-room 来源链认证；
- cc-sessions-viewer 当前 MIT 元数据已登记；旧快照与 G10 原始来源仍待逐资产复核，当前禁读/禁复制边界保持；
- 依赖传递许可进入 cargo-deny 白名单流程；
- approver 签署后本报告转 Accepted，方可在 0.1 之后按判定复用。

## 8. Ancillary preservation and review limits

| ID | Retained NOTICE group | Disposition |
|---|---|---|
| M01 | Optional `intfloat/multilingual-e5-small` @ `614241f622f53c4eeff9890bdc4f31cfecc418b3`, declared MIT; model card / technical report | Preserve default-off semantic-candle, local `asg model import --dir <bundle>`, no tool download/default bundled weights; weight redistribution remains separate/deferred; no new model/license evaluation |
| D01 | candle-core / candle-nn / candle-transformers 0.10.2; MIT OR Apache-2.0 | Preserve declared optional inference group; not default-binary inclusion proof |
| D02 | tokenizers 0.22.2; Apache-2.0 | Preserve declared optional dependency, not weights |
| D03 | safetensors 0.4.5 and 0.7.0; Apache-2.0 | Preserve both resolved version instances; do not deduplicate by package name |
| D04 | rusqlite 0.40.2; MIT; bundled SQLite / libsqlite3-sys 0.38.2 | Preserve group; SQLite/FFI are separate identities in resolved reports, not automatically rusqlite's MIT |
| D05 | blake3 1.8.5; CC0-1.0 OR Apache-2.0 | Preserve declared metadata, not independent license-file verification |
| D06 | ratatui 0.30.2 / crossterm 0.29.0; MIT | Preserve both packages; not complete TUI transitive inventory |

N11's independent Contributor Covenant 2.1 / CC BY 4.0 attribution and the
existing CODE_OF_CONDUCT text remain intact. D01-D06 retain NOTICE's declared
metadata status, not a new SPDX inventory or full license-file audit. The
JSON/CSV resolved report contract in §6 remains unchanged; source reuse,
model weights and dependency notices require distinct review. Binary bundles
carry NOTICE; GitHub-generated source archives are not those workflow bundles.

Adding the six observed MIT texts and the sessiongrep copyright conservatively
preserves notices; it does not certify historical authorization, substantiality
or every obligation. Any verified mandatory omission must be repaired, not
waived by relabeling an asset or leaving a pending field. Technical checks and
AI review cannot sign the owner/approver fields or promote this Draft.
