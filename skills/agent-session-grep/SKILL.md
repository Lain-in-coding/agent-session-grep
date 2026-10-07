---
name: agent-session-grep
description: Search local AI coding-agent session history (16-provider capability matrix; 14 implemented, 2 deferred) via the agent-session-grep robot CLI or MCP server.
---

# agent-session-grep

agent-session-grep indexes local AI coding-agent transcripts into a read-only searchable catalog: full-text search, session context assembly, and evidence spans that point back into the source files. The provider capability matrix spans 16 rows — 14 implemented providers (claude-code, codex, grok-build, opencode, antigravity, pi, hermes, cursor, kimi-code, openclaw, qoder, tencent-codebuddy, cline, aider) plus 2 deferred unsupported (deepseek-harness, zcode). The authoritative per-provider maturity and field capabilities live in `docs/product/PROVIDER-MATURITY-MATRIX.md`. Reach for it when you need to recall what happened in a past coding session.

Two machine surfaces exist. Prefer the MCP server when the client supports MCP; otherwise drive the robot CLI. Never scrape human-mode output.

All examples below are synthetic: `C:/data/example.db`, fabricated ids like `ses_v1_abc123`.

## Robot CLI

Always pass `--robot`. It emits exactly one stable JSON envelope on stdout, disables progress frames and color, and keeps diagnostics on stderr.

```
agent-session-grep --db C:/data/example.db --robot search "index rebuild" --max-items 20
```

### Envelope anatomy

```json
{
  "schema_version": "1.1",
  "frame_type": "response",
  "command": "search",
  "request_id": "cli-4242-1753500000000",
  "ok": true,
  "outcome": "success",
  "data": {
    "hits": [{
      "id": "msg_v1_abc123",
      "score": 1.42,
      "session_id": "ses_v1_0123456789abcdef0123456789abcdef",
      "resume_available": true,
      "text": "index rebuild"
    }],
    "generation": 3
  },
  "warnings": [],
  "page": { "next_cursor": "eyJjb250cmFjdF9tYWpvciI6MX0.a1b2c3d4e5f60718", "has_more": true },
  "meta": { "duration_ms": 12, "generation": 3 }
}
```

- `ok` — false means an error envelope instead: `error: { code, message, retryable, details }`.
- `outcome` — `success` or `partial`; `partial` means the results are usable but truncated by a budget (see exit code 10).
- `data` — command-specific payload.
- `warnings` — honest degradations (for example unknown-precision evidence).
- `page` — pagination: feed `next_cursor` back via `--cursor` while `has_more` is true.
- `meta.generation` — index generation the result was computed against.

### Pagination loop

```text
cursor = null
loop:
  argv = [--db, DB, --robot, search, QUERY, --max-items, 20]
  if cursor != null: argv += [--cursor, cursor]
  env = parse_json(run(agent-session-grep, argv))
  consume(env.data.hits)
  if not env.page.has_more: break
  cursor = env.page.next_cursor
```

### Exit codes

| exit | meaning |
| --- | --- |
| 0 | success |
| 2 | validation error (bad arguments, invalid or expired cursor) |
| 4 | not found |
| 5 | source / file IO error |
| 6 | catalog or index error (includes retryable `writer_busy`) |
| 7 | provider / adapter error |
| 9 | protocol or schema incompatibility (includes cursor generation mismatch) |
| 10 | partial success — results are usable but truncated; raise the budget knob named in `data.truncation.reason`, or paginate |
| 70 | internal error (bug signal) |

`--help` / `--version` always exit 0 — never a configuration error. In robot/json/jsonl modes they are success envelopes, not bare text: help text or version string ride in `data.help_text` / `data.version` (ADR-0006).

### Commands

| command | purpose |
| --- | --- |
| `search "<query>"` | full-text search over messages; hits carry canonical `session_id`, `resume_available`, and bounded `text`; plain-text keywords only — FTS operators (`AND`/`OR`/`NEAR`, quotes, `*`) match literally, there is no advanced query language (ADR-0003). Facets (all optional): `--main-only`, `--subagent-only` (mutually exclusive), `--include-sidechain` (the default), `--tool-kind` (`file`/`command`/`web`/`query`/`unknown`), `--tool-name <name>` (exact match). In the TUI, `m` cycles the sidechain facet and `k` cycles the tool-kind facet (with an empty input box) |
| `handoff "<query>"` | assemble a deterministic handoff pack (`handoff-pack/v1`) from search hits; verbatim evidence and inference stay separated, no LLM call, dry-run only; each mainline entry carries authoritative `role`/`is_sidechain` facts and the pack carries the catalog `tool_activity` list; budgets `--max-evidence` (default 20), `--max-tokens` (8000), `--max-bytes` (2000000) |
| `get-session-resume <session-id>` | resolve fixed-shape read-only Resume Metadata for a canonical `ses_v1_*` id; returns nullable Provider-native Session ID and Original Working Directory, never a command or Source path |
| `get-message <message-id>` | return one message and bounded mainline neighbors; use `--session` when a shared Message belongs to multiple Sessions |
| `list <limit>` | page catalog entities in stable id order |
| `context <session-id>` | assemble one session branch with evidence spans and projected `tool_activities` |
| `get <wire-id>` | raw stored payload of one entity |
| `show <wire-id>` | structured entity view (role, text, parent, session, span) |
| `status` | catalog entity count and active generation |
| `model import --dir <bundle>` / `model status` | offline model-cache management (never networks): `import` verifies the bundle manifest and every declared SHA-256, then publishes into the local model cache (requires a `--features semantic-candle` binary); `status` reports whether the default E5 bundle is imported. Default builds stay lexical-only (bigram-hash fuzzy-lexical) |
| `providers` | report the 16-row provider capability matrix: 14 implemented (all experimental) + 2 deferred unsupported (`deepseek-harness`, `zcode`), with per-field capabilities |
| `sync --discover` | scan the 12 registered provider data roots (`claude-code`, `codex`, `openclaw`, `tencent-codebuddy`, `antigravity`, `opencode`, `pi`, `hermes`, `grok-build`, `kimi-code`, `qoder`, `cline`) and sync every source matching that root's registered extension — `jsonl` for most, `json` for `hermes`/`cline`, `db` for OpenCode's SQLite store; `cursor` and `aider` have no home-relative root and are never auto-discovered, so pass their files to `sync <file>` by path; read-only on provider files; the response reports per-provider `found`/`removed` counts and scan completeness — never file paths |
| `doctor` | health: db, schema, generation, interrupted_batches, orphaned_tool_activities, orphaned_activity_memberships (prune with `index purge-activities`) |

`get`/`show` on a missing entity return exit 4 with a `not_found` error envelope (ADR-0005).

Budget flags (accepted where meaningful): `--max-items`, `--max-bytes`, `--max-messages`. Hitting a budget is reported as `outcome: "partial"` plus `data.truncation` and exit 10 — never a silent cut.

### Session context and evidence

```
agent-session-grep --db C:/data/example.db --robot context ses_v1_abc123 --policy mainline
```

- `--policy mainline` (default) follows the parent chain root to leaf and excludes sidechains; `--policy full` returns every message in sequence order.
- `data.evidence[]` carries one span per returned message (subject to the
  `max_evidence_spans` budget): source document id, source fingerprint, and
  location fields with `precision` tiers `byte`, `line`, `record`, or `unknown`.
  The contract declares four tiers; v1 emits only `byte` and `unknown`.
- `unknown` precision means the location fields are null, and it has two
  distinct causes. Either the data was ingested before spans existed — re-ingest
  the source to restore byte precision, and a warning is emitted alongside — or
  the provider's format has no in-file byte range for a record at all
  (`opencode` and `cursor` read SQLite, `hermes` and `cline` read a
  whole-document JSON). For those four, `unknown` is the honest permanent
  answer and re-ingesting changes nothing; the per-provider column is
  `source_span` in `docs/product/PROVIDER-BETA-READINESS.md`.

### Global flags

- `--request-id run.42:a` is echoed verbatim in every frame (charset `[A-Za-z0-9._:-]`, 1-128 chars); use it to correlate envelopes with your own logs.
- `--output jsonl` streams one complete frame per line and may emit `frame_type: "progress"` frames before the final response (long `sync` runs). `--robot` never emits progress frames.
- `--offline` (global, placed before the command name) is a stable explicit fail-closed mode: any operation that would need the network is refused instead of degraded. Every current command runs locally, so it changes no behaviour today; `doctor` echoes the flag in its `offline` field.

## MCP server

Run the same binary as a stdio MCP server (tools only, sequential, read-only):

```json
{
  "mcpServers": {
    "agent-session-grep": {
      "command": "agent-session-grep",
      "args": ["--db", "C:/data/example.db", "mcp"]
    }
  }
}
```

| tool | when to use |
| --- | --- |
| `search_sessions` | full-text query; params: `query` (required), `limit`, `cursor`, `max_items`, `max_bytes`; optional `providers` (`claude`/`claude-code`/`codex`), `since`/`until`, `include_system`, `group_by_session`; facets `sidechain` (`include`/`main_only`/`subagent_only`), `tool_kind` (`file`/`command`/`web`/`query`/`unknown`), `tool_name`; each hit includes canonical `session_id` and `resume_available`; non-default facets are echoed in `data.facets` |
| `get_session_context` | pull one session branch: `session_id` (required, canonical `ses_v1_...`), `policy` (`mainline` or `full`), `level` (`raw`/`talks`/`sessions`), `max_messages`, `max_bytes`; the response includes projected `tool_activities` for the assembled messages |
| `get_session_resume` | resolve fixed-shape Resume Metadata from a canonical `session_id`; nullable `provider_session_id` and `original_working_directory`; never returns a command or Source path |
| `get_message` | return one Message and bounded mainline neighbors; params include canonical `message_id`, optional canonical `session_id`, `around`, and budgets |
| `list_sessions` | page Session entities only in stable canonical-id order |
| `generate_handoff` | assemble a deterministic handoff pack (`handoff-pack/v1`) for a query: search hits become evidence spans with authoritative source locators, mainline entries carry `role`/`is_sidechain` facts, and the pack carries the catalog `tool_activity` list; budgets `max_evidence`/`max_tokens`/`max_bytes` are enforced and cross-boundary redaction is on by default (ADR-0009); truncation is reported as `outcome: partial` |
| `list_providers` | return the complete 16-row capability matrix from the same source as CLI `providers`: 14 implemented rows with `ingestible: true` and 2 deferred unsupported rows (`deepseek-harness`, `zcode`) with `ingestible: false`; each row includes `id`, `variant`, current `maturity`, and `maturity_target` |
| `get_status` | catalog count and active generation |
| `doctor` | health probe: `db: "ok"`, schema, generation, interrupted batches |

- Tool results carry the payload twice: `content[0].text` (serialized) and `structuredContent` = `{ outcome, data, redaction, warnings, page }` — the same shapes as the robot envelope. `redaction` reports whether cross-boundary redaction touched this payload (`status: none | applied`, `redacted_count`), so a `[redacted:...]` value is never mistaken for literal transcript text.
- Business failures (bad cursor, not found) come back as `isError: true` results with `structuredContent.error.canonical_code`; malformed or invalid params are JSON-RPC errors (`-32602`).
- Cursors are stateless signed tokens: a `page.next_cursor` from one `search_sessions` call works in a later call — even across server restarts — as long as the index generation is unchanged and the TTL has not passed.
- v0 executes requests sequentially; `notifications/cancelled` is accepted but is a best-effort no-op.

## Cautions

- Read-only: search/context/resume/MCP never modify your history. The MCP server opens only the `--db` store given at startup; it exposes no arbitrary file read, no SQL, no command execution.
- Two-ID contract: canonical `session_id` (`ses_v1_...`) is the catalog identity used by every tool; the Provider-native Session ID is Resume Metadata obtainable only via `get-session-resume` / `get_session_resume`. Never treat the native ID as canonical or vice versa.
- Resume Metadata is structured data only. If you need to resume a native session, take the returned `provider_session_id` and run the provider's own resume flow yourself; this tool never builds or runs that command.
- Cursor lifecycle: cursors expire after 15 minutes and die whenever new data is ingested (generation change). On `cursor_expired`, `cursor_invalid`, or `generation_mismatch`, do not retry the token — re-issue the query from page 1. Cursors are also result-set-bound: a `search` cursor only works for `search`, a `list` cursor for `list`, and a `list_sessions` cursor for `list_sessions`.
- Never parse human-mode output (the default without `--robot`); its wording can change at any time. Machine consumption is `--robot`, `--output json` / `--output jsonl`, or MCP only.
