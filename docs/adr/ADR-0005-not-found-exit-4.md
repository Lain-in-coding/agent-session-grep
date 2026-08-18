# ADR-0005：get/show 缺失实体统一返回 exit 4 not_found（发布前接受破坏性变更）

> 治理记录（Governance Record）
>
> - decision_id: ADR-0005
> - title: 缺失实体统一 exit 4 not_found
> - status: **Proposed（2026-08-13 UX review fix round）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: `schemas/robot/v1/error-catalog.json`；`scripts/install/smoke.ps1` / `smoke.sh`

## 决策

`get` 与 `show` 对缺失实体统一返回 exit 4 + `not_found` envelope（原 `get` 为 exit 0 + `payload:null`）。在同一变更中同步 `smoke.ps1` / `smoke.sh` 与 CONTRACT 草案。

## 背景

error catalog 权威定义 `not_found → exit 4`。exit 0 + null 让机器消费者无法区分"成功但空"与"实体不存在"。仓库私有、契约仍为 Draft、尚无已发布消费者，现在变更是成本最低的时点。

## 后果

- 依赖 exit0+null 的既有脚本必须迁移（两套安装 smoke 已同步）；
- 首个公开版本发布后该行为冻结，不得再改；
- 错误正文不得回显 wire/native ID（path-free、native-ID-free 契约不变，code 保留 `not_found`）。
