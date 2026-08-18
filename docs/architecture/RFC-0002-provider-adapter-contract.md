# RFC-0002：Provider Adapter Contract

> 治理记录（Governance Record）
>
> - decision_id: RFC-0002
> - title: Provider Adapter 合同（discovery / probe / fingerprint / parse + maturity + variant + staging）
> - status: **Draft**（待 R0 评审）
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0 Feasibility / Contract Gate
> - evidence_path: `docs/architecture/RFC-0002-provider-adapter-contract.md`；相关实测见 `spikes/source-snapshot/EVIDENCE.md`
> - approved_at: —
>
> 本 RFC 定义所有 Provider Adapter 必须遵守的稳定合同，是 `0.3 Integration Beta` 与 Provider Promotion Train 的规范性基础；Canonical 输出模型见 `RFC-0001-canonical-model-and-stable-id.md`，成熟度公开状态见 `../product/PROVIDER-MATURITY-MATRIX.md`。

---

## 1. 目标与非目标

**目标**：让每个 Provider 的格式差异被隔离在一个 Adapter 内，Adapter 之外的 Application/Storage/Search 只面对统一 Canonical 事件流；让"支持一个 Provider"成为可证据化、可分级晋级的动作，而不是代码存在即宣称支持。

**非目标**：不追求一次支持所有 Provider；v1.0 不提供动态加载第三方本地代码形式的插件；不在 Adapter 内做检索、存储或 UI。

## 2. Adapter Trait（最低合同）

```rust
trait ProviderAdapter: Send + Sync {
    fn manifest(&self) -> &AdapterManifest;
    fn discover(&self, ctx: &DiscoveryContext)
        -> Result<Vec<DiscoveredSource>, ProviderError>;
    fn probe(&self, source: &DiscoveredSource)
        -> Result<ProbeResult, ProviderError>;
    fn fingerprint(&self, source: &DiscoveredSource)
        -> Result<SourceFingerprint, ProviderError>;
    fn parse(
        &self,
        snapshot: &ReadOnlySourceSnapshot,
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError>;
}
```

四阶段职责边界清晰：`discover` 找候选 root；`probe` 判定 variant 与置信度；`fingerprint` 产出增量判定所需的轻量指纹；`parse` 在一致快照上流式产出 Canonical 事件。

参照 ctx 的 `ProviderCaptureAdapter`（provider/source_format/discover/probe 分层）与三级 confidence 设计，本合同的 ProbeResult 在其基础上补齐 evidence/ambiguity/compatibility_range。

## 3. ProbeResult 与 variant 探测

```text
ProbeResult
- variant_id
- provider_version?
- compatibility_range
- confidence: confirmed | high | low | ambiguous
- matched_evidence[]
- unmatched_evidence[]
- required_capabilities
- warnings[]
```

规则：
- `ambiguous` 或未知 variant 默认拒绝解析并给出可诊断证据，不做"尽量解析"；
- 同一 source 内混合版本必须显式报告；若无法证明各记录都适用同一解析规则，source 级别失败；
- additive unknown fields 默认忽略但计数并保留诊断；未知 discriminator/enum 不静默降级为已知语义，进入 `unknown` 或拒绝，规则由 variant contract 固定。

## 4. ReadOnlySourceSnapshot（一致快照读取）

**这是本 RFC 由 spike 实测支撑的核心约束**（见 `spikes/source-snapshot/EVIDENCE.md`）。

`parse` 不直接接收路径，而是接收 `ReadOnlySourceSnapshot`：打开句柄后捕获 `file_identity + captured_len + mtime + content_fingerprint`，只读取捕获范围，parse 结束前复核三元组。

实测结论（Windows + 合成 fixture）：
- 追加、截断、**等长异容替换** 三种变化都被检出；
- **等长替换必须靠 content_fingerprint**——len+mtime 不足以检出；因此生产复核必须包含内容指纹，不能只比 len/mtime；
- 检出变化即返回 `source_changed_during_read` 并丢弃该 source 的 staging，绝不提交混合时点数据。

## 5. Source-level staging 与错误矩阵

`parse` 先写入 source-local staging sink，只有完整成功且通过不变量校验后才提交 Catalog。错误按下表分级：

| 错误类 | 处理 |
|---|---|
| `record_recoverable` | 跳过该记录，source 标记 `incomplete`，允许提交 |
| `incomplete_tail` | 保留旧版本或重试，不提交半截 |
| `source_changed_during_read` | 丢弃 staging，有限重试 |
| `structural_fatal` / `ambiguous_variant` | source 整体回滚，不污染旧数据 |

同步报告区分 `committed` / `skipped` / `failed` / `ambiguous` / `missing`，不把部分成功伪装成成功。

## 6. Provider maturity 与晋级

字段能力：`native | derived | partial | unsupported | unknown`。Provider 整体成熟度：`Certified/GA | Beta | Experimental | Unsupported`，独立于字段能力，晋级必须有证据（fixture + 共享 contract + 跨 target + 回滚策略），不由代码存在自动推断。

`AdapterManifest` 必须声明：`provider_id`、支持的版本/variant 范围、maturity、能力矩阵、fixture revision、最后认证 target、已知限制。

实现注记：Rust 结构定义于 `agent-session-grep-ports::AdapterManifest`，并由
`ProviderAdapter::manifest()` 强制每个 adapter 显式提供。`last_certified_targets`
只有在具名 workflow run 于对应 target 成功后才能填写；仅配置 workflow 或本地测试
不得作为认证记录。

实现注记（bounded ingest，闭合 §7 的 release-blocking 约束）：`§7 硬约束`的
"流式解析，禁止整体加载大型 transcript，使用 bounded buffer"已在端口层落实：

- `agent-session-grep-ports::ReadOnlySource` 是只读、可重复打开的源视图；JSONL
  adapter 的生产解析经 `BoundedLineReader` 逐行流式读取，内存上界是单条记录
  （manifest `max_record_size`，8 MiB），与文件大小无关。整档格式（JSON
  array / Markdown / SQLite）无法流式解析，改为显式、受测的 `max_source_size`
  上限（JSON 系 32 MiB、SQLite 128 MiB），由 manifest 的 `streaming_support` /
  `max_source_size` / `max_record_size` 字段诚实声明——不宣称 streaming 而实际
  整读。
- 快照读取（`agent-session-grep-adapters-sqlite::source_fs`）的 capture / verify
  各以固定大小缓冲流式计算 `len + BLAKE3`，不再按文件长度分配 `Vec`；parse 阶段
  重新打开只读文件，提交前再流式复核指纹。span 的原始 byte offset（CRLF / UTF-8
  BOM / truncated tail）、等长异容替换的 fingerprint 检出、以及
  `source_changed_during_read` 的原子回滚语义均保持不变。

## 7. 硬约束（Release 阻断级）

- Adapter 只通过 `ReadOnlySourceFs` 访问已授权 root，绝不修改/移动/删除/锁定源文件；
- 流式解析，禁止整体加载大型 transcript，使用 bounded buffer；
- 禁止硬编码平台路径前缀（`/Users`、macOS `Application Support`），跨平台 round-trip 在 Windows、Linux、macOS 各测；
- 禁止扫描期写上游（反例：agf `prune_orphan_threads` 扫描期 DELETE 上游 SQLite）——以扫描前后 checksum 断言守护；
- 每条 Canonical 输出带关联具体 SourceMembership 的 SourceSpan；
- Provider 格式修复必须增加 fixture，不能只改 parser；
- Adapter 不接触 Storage、Search 或 UI。

## 8. 未决问题（R0 需回答）

1. `DiscoveryContext` 是否需要携带用户配置的自定义 root 与 exclude 规则的完整视图？
2. `SourceFingerprint` 的最小字段集（size + mtime + content_fingerprint 是否够，是否需要 head/tail 采样）？
3. mixed-version source 的"显式报告"落到 ProbeResult 还是 ParseReport？
4. 首批 GA 候选（Claude Code、Codex）的 variant 数量与历史格式跨度，决定 fixture 规模。

## 9. 借鉴与许可

- ctx（Apache-2.0）adapter trait 分层与三级 confidence：idea/adapt；
- ctx `ProviderCaptureEnvelope` 的 schema_version + 向后兼容：adapt；
- 所有 fixtures 一律按 R0 脱敏规范重造，禁止复制真实 transcript。
