# Go/No-Go Report — agent-session-grep v<version>

> Candidate template. Fill in every section and replace all placeholders.
> Do not recreate or replace the existing v0.1.0 tag/Release; any future
> publication needs a newly approved version and source.

- **Date**: <YYYY-MM-DD>
- **Source commit**: <full 40-character candidate SHA>
- **Rehearsal run ids**: <list all run ids from the runbook>
- **Operator**: <operator identifier>
- **Environment manifests**: <paths to completed manifests>

---

## 1. Privacy final check

| Check | Status | Evidence |
|---|---|---|
| Zero outbound network during supported runtime workflows | <pass/fail> | <capture log ref> |
| Cross-boundary redaction (Web/Handoff/MCP/Robot) | <pass/fail> | <spot-check notes> |
| Secret fixture never surfaces | <pass/fail> | <fixture + output ref> |
| No transcript leak in logs/diagnostics | <pass/fail> | <log audit notes> |

**Residual privacy risks**: <list or "none identified">

---

## 2. Performance final check

| Check | Status | Evidence |
|---|---|---|
| Gate D invariant 1 — <name> | <pass/fail> | <benchmark report ref> |
| Gate D invariant 2 — <name> | <pass/fail> | <benchmark report ref> |
| Gate D invariant 3 — <name> | <pass/fail> | <benchmark report ref> |
| Gate D invariant 4 — <name> | <pass/fail> | <benchmark report ref> |
| Gate D invariant 5 — <name> | <pass/fail> | <benchmark report ref> |
| Gate D invariant 6 — <name> | <pass/fail> | <benchmark report ref> |
| Benchmark report refreshed | <pass/fail> | <report path> |

**Residual performance risks**: <list or "none identified">

---

## 3. Release materials final check

| Check | Status | Evidence |
|---|---|---|
| README ↔ quickstart consistency | <pass/fail> | <notes> |
| Comparison table ↔ benchmark numbers | <pass/fail> | <notes> |
| Demo dataset ↔ quickstart commands | <pass/fail> | <notes> |
| LICENSE present and correct | <pass/fail> | <file ref> |
| Third-party attributions complete | <pass/fail> | <file ref> |
| Fixture provenance documented | <pass/fail> | <notes> |
| Four target archives, manifests and SHA256SUMS validated | <pass/fail> | <receipt ref> |
| Managed install/update/recovery/uninstall receipts complete | <pass/fail> | <receipt ref> |

**Residual materials risks**: <list or "none identified">

---

## 4. Five-entry-point consistency

| Entry point | Status | Notes |
|---|---|---|
| CLI JSON (`--output json`) | <pass/fail> | |
| MCP JSON-RPC | <pass/fail> | |
| Robot JSON (`--robot`) | <pass/fail> | |
| Web/HTTP (real loopback server) | <pass/fail> | |
| TUI headless (`--snapshot-json`) | <pass/fail> | |

All five surfaces must be directly compared by the existing harness.
Its `pending`, `skipped`, `aliases`, and `unimplemented` lists must be empty;
a missing result, skip, or alias is a failed gate, never an acceptable pass.
The TUI snapshot checks the structural projection, not interactive terminal UX.

**Consistency report**: <path to compare_entrypoints.py output>
**Overall verdict**: <consistent | divergent>

---

## 5. Provider evidence

### 5.1 Managed package and six-host core flow

| Check | Status | Evidence |
|---|---|---|
| `x86_64-pc-windows-msvc` install and native flow | <pass/fail> | <run/evidence ref> |
| `x86_64-unknown-linux-gnu` install and native flow | <pass/fail> | <run/evidence ref> |
| `x86_64-apple-darwin` install and native flow | <pass/fail> | <run/evidence ref> |
| `aarch64-apple-darwin` install and native flow | <pass/fail> | <run/evidence ref> |
| Claude Code MCP invocation/history retrieval/continuation | <pass/fail> | <native receipt ref> |
| Codex MCP invocation/history retrieval/continuation | <pass/fail> | <native receipt ref> |
| WorkBuddy MCP invocation/history retrieval/continuation | <pass/fail> | <native receipt ref> |
| ZCode MCP invocation/history retrieval/continuation | <pass/fail> | <native receipt ref> |
| DeepSeek Harness MCP invocation/history retrieval/continuation | <pass/fail> | <native receipt ref> |
| Antigravity MCP invocation/history retrieval/continuation | <pass/fail> | <native receipt ref> |
| Six-host cross-retrieval ring | <pass/fail> | <ring receipt ref> |
| Selected-history background refresh | <pass/fail> | <status/latest evidence ref> |
| User-triggered upgrade and intentional failure recovery | <pass/fail> | <journal/recovery ref> |
| Managed default uninstall removes only owned state | <pass/fail> | <cleanup receipt ref> |
| Managed keep-data uninstall retains catalog and policy | <pass/fail> | <cleanup receipt ref> |
| Reinstall and repeated cleanup are idempotent | <pass/fail> | <run receipt ref> |

### 5.2 Provider evidence

| Provider | Tier | Evidence | Notes |
|---|---|---|---|
| Claude Code | <certified/GA/beta/experimental> | <evidence ref> | |
| Codex | <certified/GA/beta/experimental> | <evidence ref> | |
| WorkBuddy | <certified/GA/beta/experimental> | <evidence ref> | |
| ZCode | <certified/GA/beta/experimental> | <evidence ref> | |
| DeepSeek Harness | <certified/GA/beta/experimental> | <evidence ref> | |
| Antigravity | <certified/GA/beta/experimental> | <evidence ref> | |

---

## 6. Defects found during rehearsal

| # | Description | Severity | Status | Fix ref |
|---|---|---|---|---|
| 1 | | | | |

---

## 7. Residual risk summary

<numbered list of all residual risks across all sections>

---

## 8. Recommendation

- [ ] **Go** — proceed with public release
- [ ] **No-Go** — address residual risks first

**Rationale**: <one paragraph>

---

## 9. Owner sign-off

| Field | Value |
|---|---|
| Decision | <go / no-go> |
| Date | <YYYY-MM-DD> |
| Owner | QIN |
| Signature | <owner signature> |
