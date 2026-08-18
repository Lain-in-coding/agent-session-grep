<!-- TRELLIS:START -->
# Trellis Instructions

These instructions are for AI assistants working in this project.

This project is managed by Trellis. Shared workflow knowledge lives under `.trellis/`; local journals are optional and non-authoritative:

- `.trellis/workflow.md` — development phases, when to create tasks, skill routing
- `.trellis/spec/` — package- and layer-scoped coding guidelines (read before writing code in a given layer)
- `.trellis/tasks/` — active and archived tasks (PRDs, research, jsonl context)
- `.trellis/workspace/` — optional per-developer local journals; never current-state authority

If a Trellis command is available on your platform (e.g. `/trellis:finish-work`, `/trellis:continue`), prefer it over manual steps. Not every platform exposes every command.

If you're using Codex or another agent-capable tool, additional project-scoped helpers may live in:
- `.agents/skills/` — reusable Trellis skills
- `.codex/agents/` — optional custom subagents

Managed by Trellis. Edits outside this block are preserved; edits inside may be overwritten by a future `trellis update`.

<!-- TRELLIS:END -->

# agent-session-grep Repository Onboarding

## Tooling boundary

Trellis and the platform integration roots (`.trellis/`, `.agents/`,
`.codebuddy/`, and `.codex/`) are development workflow tooling. They are not
agent-session-grep product features, provider adapters, or user-facing Skills.
Product behavior lives in the Rust crates, schemas, and product documentation.

## Clean-clone quick start

Run these commands from the repository root. The two `--help` commands are the
authoritative way to confirm the installed workflow CLI before using it.

```text
python ./.trellis/scripts/task.py --help
python ./.trellis/scripts/get_context.py --help
python ./.trellis/scripts/task.py list
python ./.trellis/scripts/task.py current --source
python ./.trellis/scripts/get_context.py --mode packages
```

`task.py current --source` exits nonzero when no task is active; that is a
normal clean-clone state. If it does, use `task.py list`: the sole shared task
with `status=in_progress` is the repository's current work, while a runtime
pointer only records the current session's selection. Before creating or
starting a task, follow `.trellis/workflow.md`, including its consent and
planning gates.

## Authority order

When sources disagree, use this order:

1. The user's current request and repository-level instructions.
2. The active task under `.trellis/tasks/`.
3. Applicable contracts in `.trellis/spec/` and the lifecycle in
   `.trellis/workflow.md`.
4. RFCs, ADRs, schemas, and other formal records under `docs/` and `schemas/`.
5. Executable evidence: tests, CI results, and spike evidence.
6. Git history for historical context only.

Legacy plans, handoff notes, workspace journals, and runtime pointers are not
current-state authorities.

## Active-task read order

Resolve the task with `task.py current --source`. For an implementation or
check agent, read the applicable `implement.jsonl` or `check.jsonl` entries and
the files they reference first, then read `prd.md`, `design.md` if present, and
`implement.md` if present. Consult `task.json` for lifecycle metadata; do not
treat it as a replacement for the requirements and design artifacts.

## Local and generated state

Do not share or commit developer identity, runtime task pointers, caches,
backups, transcripts, local journals, credentials, machine-specific approvals,
or personal paths. In particular, content under `.trellis/.runtime/` and local
identity or workspace state is not shared project truth.

Platform integration trees intentionally contain generated or duplicated
Trellis assets so supported tools can operate from a clone. Do not infer
agent-session-grep product behavior from them. Files marked as managed or generated
may be replaced by a Trellis update; change their canonical source and
regenerate them rather than relying on hand edits to generated copies.

Cloning the repository does not automatically trust or enable project-level
agent integrations. Review the checked-in configuration, then use each
platform's user-level trust, approval, or enablement controls before running
hooks, Skills, agents, or commands.
