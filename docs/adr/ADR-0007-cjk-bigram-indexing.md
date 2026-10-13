# ADR-0007：CJK 检索采用索引期 bigram 预处理

> 治理记录（Governance Record）
>
> - decision_id: ADR-0007
> - title: CJK 检索索引期 bigram 预处理
> - status: **Proposed（2026-08-13 下轮规划，owner 裁定）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: 5 路体验/审查实证（ux-newbie/ux-search/ux-mcp/review-features 中文召回 8-33%）；ADR-0001 §后果

## 决策

CJK 连续序列在**索引写入前**做 n-gram 预处理：每段连续汉字切分为单字（unigram）与相邻两字（bigram）并以空格连接（"配置备份" → "配 置 备 份 配置 置备 备份"），作为 FTS 词元写入；查询侧同一 transform。bigram 覆盖双字及以上子串，unigram 覆盖单字查询（如"了"）。FTS 仍为可重建投影，迁移走 `index rebuild`（catalog 不动、generation 推进）。

## 背景

FTS5 默认 unicode61 把整段连续汉字当一个词元，实测中文召回 8-33%，`search 配置`/`search 数据库` 这类双字核心查询大面积 miss。ADR-0001 §后果 承诺的"backend-neutral analyzer 预分析（CJK bigram）"从未落地。trigram tokenizer（SQLite 3.50 内置）对 ≤2 字查询失效——而双字词正是中文检索最常见单位，故否决；双列（原文列 + 预处理列）作为后续增强，不阻塞本轮。单字查询的 unigram 词元在同一条 token 流中追加（2026-08-25 落地），不做全量 scriptgram 表（ctx 的自研 tokenizer）或 schema 级 trigram（memex）。

## 后果

- FTS 内容语义变化：索引重建（`index rebuild`）后生效，cursor 因 generation 推进失效属正常契约行为；
- 词元数约 4x（单字 + bigram 相对词级分词），索引体积相应膨胀，可接受；
- 单字 CJK 查询（如"了"）由 unigram 词元覆盖，不再落空；
- 与 plain-text-only（ADR-0003）兼容：n-gram 变换发生在字面词元之后，不恢复任何高级语法。
