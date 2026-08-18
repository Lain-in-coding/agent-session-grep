# ADR-0006：机器模式下 help/version 走 success envelope（不输出裸文本）

> 治理记录（Governance Record）
>
> - decision_id: ADR-0006
> - title: 机器模式 help/version 输出协议 envelope
> - status: **Proposed（2026-08-13 UX review fix round）**
> - owner: （待指派）
> - approver: 项目最终验收人
> - due_milestone: R0
> - evidence_path: `docs/contracts/CONTRACT-cli-robot-mcp-draft.md` §6；parser/protocol reviewer 复现

## 决策

`--help` / `--version` 在任何输出模式下恒 exit 0：human 模式打印文本；robot/json/jsonl 模式返回 success envelope，帮助文本或版本号放在 `data` 字段。不存在"机器模式下 help 报错"的状态。

## 背景

review 复现 `--robot search --help` 输出裸文本且吞参数，违反"robot stdout 只允许协议 frame"的契约。备选方案是机器模式下拒绝 help（invalid_request）或仅 version 走 envelope，但两者都会让同一命令在不同模式下退出码不同。

## 后果

- help/version 语义上不是错误，exit 0 恒成立，脚本行为可预测；
- envelope schema 已允许 command-specific `data`，新增 `help`/`version` 字符串字段不破坏版本化契约；
- 机器消费者仍应读 schema/contract 获取权威信息；envelope 帮助文本只是便利。
