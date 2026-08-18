# Go/No-Go Report — agent-session-grep v0.1.0 (draft, 2026-08-16)

> Non-template draft. Conclusion is **No-Go**: local P0 gaps and external
> release gates remain open. This draft records the rehearsal evidence and the
> residual risks; it is submitted for the owner's final decision, not as a
> release authorization.

- **Date**: 2026-08-16
- **Rehearsal run ids**: Windows Round 1 (`install-windows-2026-08-16`,
  `ingest-windows-2026-08-16`, `search-windows-2026-08-16`,
  `context-windows-2026-08-16`, `resume-windows-2026-08-16`,
  `handoff-windows-2026-08-16`, `consistency-windows-2026-08-16`,
  `uninstall-windows-2026-08-16`, `reinstall-windows-2026-08-16`);
  WSL Linux side (fmt/clippy/test, release build, verify-release) recorded in
  aggregate; macOS rehearsal **not run** (external CI-billing blocker).
- **Operator**: QIN (recorded in task system)
- **Environment manifests**: `docs/release/environment-manifest.template.json`
  (template); local Windows/WSL evidence recorded in aggregate — OS/build,
  commit, and hashes only, no personal paths.

---

## 1. Privacy final check

| Check | Status | Evidence |
|---|---|---|
| Zero outbound network during supported runtime workflows | **pass (static)** | global `--offline` landed (fail-closed `capability_not_supported`); `tests/network_egress.rs` + `security-audit` step assert zero-egress default build; clean-env Wireshark capture drill still pending |
| Cross-boundary redaction (Web/Handoff/MCP/Robot) | **pass** | shared `redact.rs` engine; Round 3 redaction fix + synthetic secret fixture e2e (b1060d4); Web/JSON boundary redacted |
| Secret fixture never surfaces | **pass** | synthetic secret fixture verified; embedded-prose shapes covered |
| No transcript leak in logs/diagnostics | **pass** | diagnostic audit clean |

**Residual privacy risks**:
- Public tree/history scrub landed (P0-1 closed): `scripts/evidence/privacy_scan.py`
  scans tracked text for personal/machine absolute paths (0 findings on current
  HEAD); the history-rewrite decision
  (`docs/operations/PUBLIC-HISTORY-SCRUB.md`) remains an owner decision.
- Redaction ruleset is a conservative subset; enterprise/custom token formats
  are not covered.

---

## 2. Performance final check

| Check | Status | Evidence |
|---|---|---|
| Gate D invariants (all six) | **pending** | runbook §11 remains pending; Gate D benchmark suite not yet run against the rehearsal corpus |

**Residual performance risks**: none measured; Gate D evidence outstanding.

---

## 3. Release materials final check

| Check | Status | Evidence |
|---|---|---|
| README ↔ quickstart consistency | pass | installer/docs sync (919b48e, 9014546) |
| Comparison table ↔ benchmark numbers | pass | `--offline`/semantic over-claims removed (e506288) |
| Demo dataset ↔ quickstart commands | pass | fixture provenance documented |
| LICENSE present and correct | pass | MIT + Apache-2.0, REUSE audit pending owner signing |
| Third-party attributions complete | **pass (factual NOTICE landed)** | `NOTICE` now ships in every release archive; approval of the reuse matrix remains owner-signed (REUSE audit Draft) |
| Fixture provenance documented | pass | synthetic gate fixtures, license + redaction recorded |

**Residual materials risks**: factual `NOTICE` + machine-readable third-party
inventory now land in every archive; the REUSE reuse-matrix approval and any
formal SBOM certification decision remain owner-signed (Draft).

---

## 4. Five-entry-point consistency

| Entry point | Status | Notes |
|---|---|---|
| CLI robot JSON | **pass** | `--output json` canonical projection |
| MCP JSON-RPC | **pass** | `search_sessions` structuredContent, same render projection |
| Robot envelope | **pass** | explicit `--robot` invocation, same canonical payload |
| Web/HTTP | **pass** | real loopback `serve` + bearer token, `GET /api/projection/search` |
| TUI automated | **pass** | headless `tui --snapshot-json <query>` shared Application projection |

**Consistency report**: `scripts/rehearsal/compare_entrypoints.py` output —
`overall_verdict: consistent`, all five entry points compared, no skipped /
aliased / unimplemented surfaces.
**Overall verdict**: **consistent** (this check).

Note: this check covers the fixed canonical search operation. Web/TUI do not
expose a comparable list-sessions projection; the harness deliberately scopes
the comparison to the search contract rather than weakening it to skipped.

---

## 5. Provider evidence

| Provider | Tier | Evidence | Notes |
|---|---|---|---|
| Claude Code | experimental | golden + byte-assert round-trip (243d7d5) | certified target, not reached |
| Codex | experimental | incremental resync/tombstone e2e (432744f) | certified target, not reached |
| 12 others | experimental | manifest entries, no external golden | `known_limitations` incomplete |
| deepseek-harness, zcode | unsupported | deferred, no transcript evidence | — |

Provider matrix `providers` reports 16 rows; PRD requires ≥5 Beta + Claude/Codex
certified — currently 0 Beta. **Not release-ready per provider gate.**

---

## 6. Defects found during rehearsal

| # | Description | Severity | Status | Fix ref |
|---|---|---|---|---|
| 1 | verify-release.py ran 5 checks but docstring claimed full flow | P0-5 | closed | this task |
| 2 | Web/TUI allowed skip-as-pass in the consistency harness | P0-5 | closed | this task |
| 3 | handoff subcommand missing (round 1) | P0 | closed | 4f98fc2 |
| 4 | serve not wired to Application ADT (round 1) | P0 | closed | 355186a + 46e4c5f |
| 5 | Web/JSON boundary leaked secrets (round 3) | P0 | closed | b1060d4 |
| 6 | handoff created_at invalid timestamp | P0 | closed | 8cc165e |
| 7 | serve token generator not CSPRNG | P0 | closed | 0630971 |

---

## 7. Residual risk summary

1. **P0-4**: release pipeline configured but never a named successful run; CI
   billing blocks all jobs; factual NOTICE landed and ships in archives;
   REUSE reuse-matrix approval + SBOM certification decision remain owner-signed.
2. **Provider maturity**: 0 Beta; Claude/Codex not certified against the PRD
   gate — remains below the ≥5 Beta requirement.
3. **External**: GitHub Actions billing; PRIVATE→public switch (Option-A public
   tree exporter `scripts/release/export_public_tree.py` is ready and current-tree
   privacy gates are green), tag, GitHub Release; Authenticode/notarization/cosign;
   branch protection; ADR signing/owner decisions.
4. **macOS**: rehearsal not run (external CI-billing blocker).
5. **Known deferred**: real local semantic model **weights delivery + recall
   benchmark gate** (the optional `semantic-candle` runtime and the offline
   `model import` / `model status` path are now implemented; default builds
   stay bigram-hash / lexical-only and must not be marketed as semantic).
   Robot capability UI and ToolActivity retention/cleanup policy remain
   explicitly deferred. The current default `bigram-hash-v1` vectorizer
   remains honestly labeled fuzzy-lexical, not semantic.

Closed since this draft's original date: P0-1 privacy scrub, P0-6 bounded
ingestion, handoff determinism/budget/redaction, resume first-run preview,
`--offline` + hook provider/time filters, ToolActivity search facets + schema
v12, serve hardening, P0-5 release rehearsal (verify-release 10/10, five-entry
consistency harness all-direct).

Closed by the 2026-08-17 release-gap wave (post-draft audit fixes, pushed to
`main` at `ed57a9a`): Robot v1.1 `searchData.facets` schema echo + protocol
flag-skip parity; Web/MCP canonical provider ids (`claude-code`/`codex`); root
installer scripts delegate to canonical `scripts/install/`; MCP facets echo +
`list_providers` 16-row matrix projection + Web `/api/providers` standard
envelope; gate-smoke PowerShell flag style + self-copy hazard; CI runs Python
release/evidence suites and gates release on green CI; workflow actions pinned
to SHAs; `security-audit.yml` gains `pull_request` trigger; redaction covers
fine-grained GitHub PATs + embedded AWS secret keys + MCP error frames + hook
headers; serve token compare made constant-time + `frame-ancestors 'none'` CSP;
`deny.toml` bans HTTP-client crates; spikes get standalone `[workspace]`
markers; privacy scanner drops hardcoded operator username and scans all
tracked paths (0 findings); 16-row capability-matrix drift test; tracked
generated gate manifest untracked per out/README contract; THREAT-MODEL gains
serve-LAN/hook/model-download/embedding-API attack surfaces; roadmap phase
snapshot refreshed to `NOT_READY_EXTERNAL_BLOCKERS`.

Closed by the post-release-gap wave (pushed to `main` at `f7e2a49`): optional
`semantic-candle` backend + offline `model import`/`model status` (default
build stays lexical-only, never downloads); handoff packs project catalog
`tool_activity` and authoritative `role`/`is_sidechain` facts; TUI search
facet controls (`m` sidechain / `k` tool-kind); context responses project
`tool_activities`; provider Beta readiness ledger
(`docs/product/PROVIDER-BETA-READINESS.md`) separates local from external
promotion blockers.

---

## 8. Recommendation

- [ ] **Go** — proceed with public release
- [x] **No-Go** — address residual risks first

**Rationale**: The five-entry-point consistency harness and the release
verification script are now green on the local Windows/WSL rehearsal evidence
(P0-5 closed), and the local P0/P1 feature waves have all landed (privacy
scrub, bounded ingestion, offline, resume/handoff, ToolActivity facets,
serve hardening). Release readiness is not equivalent to those checks: P0-4
(release pipeline has no named successful run and CI is blocked by billing;
SBOM/NOTICE/REUSE audit open), the provider maturity gate (0 Beta,
Claude/Codex not certified), and the macOS clean-environment rehearsal remain
open pending the external billing blocker and owner decisions. The owner
should treat this draft as the evidence summary for a No-Go decision and
re-run the affected sections after the open external items close.

---

## 9. Owner sign-off

| Field | Value |
|---|---|
| Decision | <pending — draft recommends No-Go> |
| Date | <pending> |
| Owner | QIN |
| Signature | <recorded in task system> |
