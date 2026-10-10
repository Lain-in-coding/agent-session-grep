# Provider Beta Readiness Ledger

> Machine-readable companion to `PROVIDER-MATURITY-MATRIX.md`.
> Authority for maturity/capability values remains
> `crates/agent-session-grep-ports/src/capability.rs`.
> This ledger records **why no provider is Beta yet** and separates
> repository-local gaps from external/owner gates. Do not promote from this
> file alone.

Last updated: 2026-10-06 (lifecycle wave (B5) — provider-level append / shrink / same-length rewrite / fork evidence for `claude-code` and `codex` landed in each crate (see the lifecycle section below); no maturity, capability or blocker column changes).

Previous pass, 2026-09-29 (provider coverage wave: `hermes` gained the additive
`hermes/sqlite-state-v1` variant for `~/.hermes/state.db` and
`~/.hermes/profiles/<name>/state.db` — bounded read-only snapshot, dual-shape
tool-call decoding, synthetic golden + PROVENANCE, no new resume command. The
columns below are unchanged: the capability row still advertises the JSON
variant, and the remaining local gaps are recorded in the hermes row. No
promotion is implied; the owner decision and the global blockers still apply).
Previous pass, 2026-08-28 (local-gap closure pass: `kimi-code` now indexes user
prompts (`turn.prompt` / `turn.steer`) — the earlier gap left the highest-value
text out of the index entirely; the three remaining "pending" items are resolved
into recorded decisions instead of open work: `tencent-codebuddy`'s extension
surface has no format evidence in any reference project, `opencode`'s
`source_span` is structurally unavailable in a SQLite source, and `pi`'s
`context` blocker is the identity-architecture decision recorded below.
Previous wave, 2026-08-27: richer tool-call extraction wave: `claude-code` /
`codex` tool_activity extraction now matches the record shapes real
transcripts write — codex registers `function_call` and pairs both
`*_call_output` types by `call_id`, reads the string `input` of
`custom_tool_call`, and resolves `apply_patch` envelopes to the patched path;
the kind closed set gained the tool names a real-corpus census found; Claude
`tool_use` blocks now render as `Name(target)` summaries in the canonical body,
so tool-use-only assistant messages are no longer indexed with empty text.
Both stay `partial` — the residual limits are recorded per row, not fixed.
Earlier, 2026-08-25: resume matrix `antigravity` / `opencode` /
`kimi-code` / `tencent-codebuddy` resume column → `derived`, evidence per row;
tool_activity honesty wave: seven formats reviewed — four carry structured tool
records but no per-message native id to anchor, three carry none — all seven
stay `Unsupported` with the reason recorded per row and pinned by golden-corpus
drift tests.)

## Recorded architectural decision: document-scoped native message identity

`pi` — and any future format whose record ids are file-scoped — cannot publish
parent edges today, and the reason is an identity contract rather than a missing
parser. Canonical message identity adopts a provider-native id **verbatim and
without a provider namespace** (`StableId::native`), which is exactly what lets
the same message copied into two transcripts merge into one entity: a
load-bearing property behind cross-source dedup and the shared-message union
tests. Real Pi record ids are 8 hex characters scoped to a single file, so
adopting them verbatim would merge unrelated messages from different sessions
onto one entity — worse than having no edges at all.

Making them usable requires a document-scoped identity mode (native id
namespaced by its source document before hashing), declared per provider and
honoured by the composition root and the parent-edge resolver together. That
changes the identity contract itself, so it is recorded here as a decision to
take deliberately — with its own migration and test wave — rather than folded
into a provider patch. Until then `pi`'s `context` and `tool_activity` stay
Unsupported with the reason stated per row, and the adapter reports the
un-modeled lineage as an explicit parse diagnostic so the omission is visible
instead of silent.

## Recorded follow-ups from the Hermes `state.db` variant (2026-09-29)

Recorded, not silently accepted: each row is a measured, user-visible or
contract-level consequence that needs an owner decision or a separate change.
None of them is a promotion, and none changes any column in the tables below.

| Follow-up | Measured effect | Owner action |
|---|---|---|
| Whole-source ceiling for `hermes/sqlite-state-v1` | The adapter's own snapshot cap is 128 MiB, but the provider manifest keeps this format in the whole-source family with the JSON variant's 32 MiB `JSON_FAMILY_MAX_SOURCE_BYTES`, so the selection layer rejects a larger `state.db` before the adapter runs (explicit `SourceTooLarge`, never truncation). A real Hermes database can exceed 32 MiB. | Decide whether this variant gets a wider whole-source bound (a manifest/capability-contract change, with the JSON variant's accepted input left unchanged), or whether 32 MiB stays the documented ceiling. |
| Count-based limits are reported in "bytes" | `ProviderError::SourceTooLarge` / `RecordTooLarge` are phrased in bytes, so count ceilings surface as e.g. `33 bytes exceeds supported limit 32` (tool calls) or `4097 bytes exceeds supported limit 4096` (sessions). The wording is hard-coded in the shared port error and was deliberately not changed here. | Decide whether the shared error type gains unit-aware wording (or the adapter wraps counts in a dedicated variant) so user-facing diagnostics do not misstate what exceeded the limit. |
| Probe-error attribution when a source exceeds the whole-source ceiling | The selection layer keeps only the last probe failure, so a `state.db` over the 32 MiB ceiling can surface as a *different* adapter's probe error (measured: Cursor's, on the same file). The honest cause (size) is not what the user sees. | Decide whether selection reports all probe failures (or the size rejection) instead of the last one. |

## Lifecycle evidence (2026-10-06, B5)

Provider-level lifecycle scenarios for the two high-frequency JSONL providers.
Synthetic fixtures only; this section adds anchors, not promotions.

- `claude-code` / `codex`: append, shrink (line boundary / torn tail / empty
  source), same-length rewrite (text and native id) and fork-edge scenarios are
  covered in each crate's `tests/lifecycle.rs`. The append prefix-stability
  invariant — unchanged records keep their seq, identity, parent edge, text and
  span when a snapshot grows — is additionally randomized over the existing
  64-seed generators in `tests/properties.rs`
  (`prop_append_keeps_prefix_byte_stable`). The provider contract sees only
  snapshot bytes (no path, no previous parse), so these tests pin prefix
  stability and honest degradation, never sync watermarks.
- `codex` fork: N/A at the provider layer — the rollout format has no parent
  field and the adapter hard-codes `parent_native_id: None`; a negative test
  pins that copied prefixes and `event_msg` mirrors never fabricate threading or
  double-count.
- File move: N/A at the provider layer (no path input); locator- and
  identity-preserving move semantics live in
  `crates/agent-session-grep-adapters-sqlite/src/relocation/tests.rs` and the CLI
  relocation e2e.
- SQLite WAL: N/A for both JSONL providers; WAL capture / WAL-only change
  detection evidence is in
  `crates/agent-session-grep-adapters-sqlite/src/source_fs.rs`.
- Native resume: not executed in this environment; the `resume` column records
  CLI-command evidence only and is unchanged by this wave.

## Global external blockers (apply to every promotion)

| Blocker | Owner | Notes |
|---|---|---|
| Named successful cross-target CI run | external CI | `last_certified_targets` stays empty until a green Windows/Linux/macOS run id is recorded |
| ADR-0010 accepted_at | owner/approver | Rollback policy is Proposed only |
| Independent owner promotion decision | owner | RFC-0002 §6 forbids code-existence promotion |

## Per-provider local readiness (implemented 14)

Legend for local columns: `ok` = present with tests; `partial` = present with known holes; `missing` = not implemented / unsupported in capability matrix. `property` = seeded randomized property suite (`tests/properties.rs`, mirroring claude-code/codex).

| provider_id | golden | read-only | property | discover | source_span | tool_activity | resume | incremental | local Beta blockers (beyond global) |
|---|---|---|---|---|---|---|---|---|---|
| claude-code | ok | ok | ok | native | ok (native) | partial | derived | derived | tool_activity stays `partial` by format, not by missing work: kind comes from a closed set of documented tool names, so user-defined and MCP (`mcp__*`) tools are recorded with kind `unknown` (guessing a kind from an arbitrary name would be fabrication), and a call whose `tool_result` never arrives reports status `unknown`. No other local gap; owner promotion still required |
| codex | ok | ok | ok | native | ok (native) | partial | derived | derived | tool_activity stays `partial` by format: rollout tool outputs carry no failure marker at all (no `is_error`, no `metadata.exit_code` in 12805 observed outputs), so status is success-or-unknown and `error` is unreachable without inventing it; `web_search_call` / `tool_search_call` records carry neither a tool name nor a `call_id`, so they are not extracted; rollout has no sidechain concept, so actor is always `main`. No other local gap; owner promotion still required |
| grok-build | ok | ok | ok | native | ok (native) | missing | derived | derived | format carries structured tool records (`_meta.bashCommand` meta chunks) but no per-message native id — tool_activity cannot anchor, honestly Unsupported; synthetic msg ids |
| antigravity | ok | ok | ok | native | ok (native) | missing | derived | derived | no in-file session id; format carries `tool_calls` on step records but `step_index` is not a durable cross-document id — tool_activity cannot anchor, honestly Unsupported |
| opencode | ok | ok | ok | native | missing | missing | derived | derived | `source_span` is structurally unavailable, not pending: a span is a contiguous byte range in the verified source, and message text inside a SQLite file lives in B-tree cell payloads that (a) spill across overflow pages, so no single `[start, end)` range holds a record's text, and (b) move on any page split or `VACUUM`, so an offset is not stable across writes. Unlike aider's `derived` spans — whose source is a real text file with genuine byte offsets — a synthesised offset here would point at wrong bytes while passing the bounds check. Decided, not deferred |
| pi | ok | ok | ok | native | ok (native) | missing | derived | derived | format v2/v3 is a parent-linked session tree (`version` header + per-record `id`/`parentId`) and carries `toolCall`/`toolResult` records; the adapter indexes every branch linearly and reports the un-modeled lineage as an explicit parse diagnostic, but emits no parent edges and no tool activity — Pi record ids are 8-hex, file-scoped, and canonical message identity adopts native ids verbatim without a provider namespace, so promoting them would collide across sessions. context/tool_activity stay Unsupported until document-scoped native message identity lands in the composition root |
| hermes | ok | ok | ok | native | missing | missing | unknown | derived | JSON doc plus the additive SQLite `state.db` variant (`hermes/sqlite-state-v1`): bounded read-only snapshot over a private copy of the captured bytes (one pinned read transaction, no main/WAL/SHM copy race), synthetic golden with per-message session membership and parse accounting (`crates/agent-session-grep-provider-hermes/tests/golden/state.db`, provenance in the same directory), both documented tool-call shapes decoded. Still no span; tool associations stay non-authoritative (no call id synthesized, no parent edge, no tool activity emitted), so the `tool_activity` column stays missing. Messages report no adopted native id: `messages.id` is a per-database rowid and canonical message identity carries no provider namespace, the same document-scoped-identity blocker recorded for `pi`. `state.db` needs explicit-path ingest (the discovery table is a single-root map) and an already registered shallower installation root currently absorbs `~/.hermes/profiles/<name>/state.db` (pinned by `known_limitation_main_database_absorbs_a_profile_source` in `crates/agent-session-grep-cli/tests/hermes_state_db.rs`). Resume evidence conflicting across reference projects (agf `hermes --resume <id>` vs hstry `hermes --session <id>` vs cc-switch/AgentRecall no CLI) — stays unknown |
| cursor | ok | ok | ok | missing | missing | missing | unknown | derived | no discovery root: the adapter parses the VS Code `workspaceStorage/*/state.vscdb` surface (ItemTable `chatdata`/`prompts` plus the additive `cursor/disk-kv-v1` `cursorDiskKV` composerData/bubbleId variant), whose per-workspace hash directories sit under a platform-specific application-data path, not a home-relative root this table can express; `~/.cursor/chats/<id>/store.db` is the separate Cursor CLI `meta`/`blobs` schema, which this adapter's probe rejects. The disk-kv variant reads a private read-only snapshot under one pinned read transaction (the source DB/WAL is never opened), follows `fullConversationHeadersOnly` for message order, counts missing/NULL/malformed/wrong-shape/invalid-UTF-8 bubbles in `skipped` with per-slot diagnostics, and adopts no native message id (a `bubbleId` is a composer-scoped storage-key component, so canonical identity stays document-scoped - the same decision as hermes rowids). No span; multi-gen format layering pending; Cursor CLI resume (`agent --resume`) is a different surface than this adapter — stays unknown |
| kimi-code | ok | ok | ok | native | ok (native) | missing | derived | derived | user prompts (`turn.prompt` / `turn.steer`) are now indexed as user messages — the earlier gap left the highest-value text out of the index entirely; `context.append_loop_event` step/tool events stay unparsed because they are tool activity rather than messages and wire.jsonl carries no per-message native id to anchor them, so tool_activity remains honestly Unsupported |
| openclaw | ok | ok | ok | native | ok (native) | missing | unsupported | derived | resume intentionally unsupported; format carries no structured tool-call records — tool_activity honestly Unsupported |
| qoder | ok | ok | ok | native | ok (native) | missing | unknown | derived | discovery covers the transcript-JSONL surface only (the Electron SQLite store is a separate, unimplemented surface); format carries `tool_use`/`tool_result` records but no per-message native id — tool_activity cannot anchor, honestly Unsupported; no authoritative resume command in reference projects (AgentRecall: resume false) |
| tencent-codebuddy | ok | ok | ok | native | ok (native) | missing | derived | derived | the VS Code extension surface stays unimplemented for lack of format evidence, not for lack of work: every reference project that reads CodeBuddy (AgentRecall's `codebuddyAdapter` in `format-adapters.ts`, ctx, cc-switch) parses the same `type: "message"` transcript-JSONL shape this adapter already handles, and none documents a separate extension store. Guessing that layout would be fabrication; documented format knowledge carries no structured tool-call records either, so tool_activity is honestly Unsupported |
| cline | ok | ok | ok | native | missing | missing | unsupported | derived | no session id / span; discovery covers the `~/.cline/data/tasks` tree only (the VS Code extension `globalStorage` tree is not home-relative and is not registered) |
| aider | ok | ok | ok | missing | derived | missing | unsupported | derived | approximate spans; no resume; no discovery root by construction — `.aider.chat.history.md` lives at the root of each user repository, so upstream agentsview discovers it by walking working trees rather than one canonical home directory; no tool_activity (blockquote tool output is folded into assistant text, no structured call/result records) |

## Deferred providers (not Beta candidates)

| provider_id | status | blocker |
|---|---|---|
| deepseek-harness | Unsupported | no transcript evidence |
| zcode | Unsupported | no transcript evidence |

## Honest promotion rule

A provider may be advertised as **Beta** only when:

1. every local Beta column above is `ok` (or an explicit, owner-approved exception is recorded);
2. a named cross-target CI success is written into `AdapterManifest.last_certified_targets`;
3. ADR-0010 is Accepted; and
4. the owner records the promotion decision with evidence paths.

Until then the public matrix stays **Experimental** for all 14 implemented providers.
