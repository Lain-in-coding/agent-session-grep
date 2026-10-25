# Robot CLI and MCP protocol reference

Read only when CLI arguments, envelopes, pagination, setup or an error need
clarifying. Normal historical lookup uses the compact workflow in
[SKILL.md](../SKILL.md); this reference is not a preflight checklist. Examples
use synthetic placeholders and are not valid stored IDs.

## Managed and legacy behavior

Managed reads use permitted original-source projections and disclose freshness.
The selected Claude/Codex worker updates history independently of queries; no
MCP tool starts ingestion or grants permission. `latest: true` with optional
`max_wait_ms` (0..30000, default 5000) requests a post-admission source/discovery
receipt within the original request budget. An unmet barrier returns permitted
evidence with a concrete partial reason, not proof of no matching history.
CLI uses `--latest --max-wait-ms <n>`. Pause keeps permitted stored evidence
readable, and reads do not resume it. Counts, generation and heartbeat alone
never establish currentness. Older unmanaged catalogs have no selected-scope
or latest-receipt contract; use only capabilities advertised by the actual build.

Current managed search/list continuations use a bounded private result cache:
512 candidates, 4 MiB per set, 64 sets/64 MiB total and a 15-minute TTL. Verified
append preserves cached order; policy, destructive changes, restore/incarnation,
query/model bindings or expiry invalidate it. Cache failure may retain a one-shot
partial result with `continuation_unavailable` and no cursor. Legacy stateless
cursors have the generation checks below. Neither cursor form grants permission.

Managed evidence defaults to five items/messages and an 8192-byte complete
Robot/MCP frame; MCP includes both payload copies. Managed handoff defaults to
five evidence items, 2048 estimated tokens and 8192 bytes, with a 256-character
query bound and at most 500 candidates. Explicit budgets can be smaller only
within schema minimums (4096 bytes, one item/message). Legacy defaults are
retained in the tables below and are not recommended lookup budgets. Byte
limits are not model-token measurements. Ordinary requests share a ten-second
admission-to-frame deadline; latest uses `max(10000, max_wait_ms + 5000)` ms,
up to 35 seconds. Waiting, SQL, retries, rendering and emission share that budget.
A partial response is not fixed by silently resetting a wait or raising all caps.

Managed `data.provenance` carries canonical anchors and verified revision digests;
`data.snapshot` discloses generation/policy/destructive epochs and `data.freshness`
reports as-of `empty|partial|complete` coverage, independent worker update state,
latest satisfaction and a concrete reason. Ordinary reads do not claim a
post-request observation; `as_of_verified` describes the last complete selected
discovery, while `discovery_pending`/`deferred` explains incomplete coverage.
Default evidence
never contains private source locators/native IDs. Nullable native session ID and
working directory are separately requested Resume Metadata. SQLite source reads
use private logical snapshots including committed WAL; source DB/WAL bytes and
history content remain unchanged, while SHM reader bookkeeping can change.

Managed tools accept `providers`, `repo`, `since` and `until` as request
intersections, including direct-ID reads and handoff enrichment. A repository
is an exact `host/owner/name` slug, not a local path. Time bounds are half-open
`[since, until)` and unknown-time evidence cannot prove a requested date. Search
excludes system/developer roles unless `include_system` is enabled; non-search
managed MCP reads currently exclude those roles. Retain every explicit filter
on follow-up calls. Legacy tools accept only the fields their schemas advertise;
legacy handoff has no `repo` field. If a tool cannot preserve a required filter,
use a supported scoped read or report the gap rather than silently widening.

## Index/setup and program update

These actions are separate from lookup, require the user's selected setup scope,
and are not performed as a search preflight. Setup creates/validates a private
managed catalog; verified packages can register explicitly selected Claude,
Codex, WorkBuddy, ZCode, DeepSeek Harness or Antigravity configuration. Current
`setup --history` accepts the six canonical provider IDs (and the `claude`
alias) only when each corresponding host is selected. All six use the managed
worker's selected-source pipeline. Synthetic lifecycle evidence is separate from
actual host loading and invocation. Later history
selection/revocation uses `sources add --provider <id> <root-or-file>` and
`sources revoke`; registering a host does not silently permit its entire history.
Background start/status/pause/resume/stop controls persisted
intent; start preserves pause/stop, resume explicitly changes intent to running.
An explicit get_message anchor defaults to around=0. It remains readable when
provider metadata interrupts the selected mainline; a missing nonzero
neighborhood returns only that anchor with context_unavailable. No fabricated
thread edge or chronological neighbor fills the gap.

Source transcripts stay read-only, while ASG owns a writable local catalog.
Missing/corrupt managed control fails closed rather than revealing legacy facts.

`update check` explicitly uses the package-verified versioned HTTPS metadata
helper. `update apply --from <archive>` is offline and also requires its sibling
manifest and `SHA256SUMS`; the current candidate path requires a newer SemVer
with catalog22/control2, or a verified catalog21/control2 to22/control2 migration.
Other schema paths are refused before maintenance. Schema rollback restores the
exact21 backup before publishing the old program pointer. `update status` inspects the retained
journal; `update recover` reconciles the recorded installation/catalog, retaining
current pause/revoke policy and freshness unknown until re-observation. Owned `background autostart enable|disable` controls future login registration
without changing desired updates. Managed uninstall/keep-data and CLI
legacy-to-managed migration remain under implementation.
Installed configuration or local tests do not establish host loading, six-host/
four-target native coverage or measured five-second acceptance.

## Robot CLI

Always pass `--robot`. It emits exactly one stable JSON envelope on stdout, disables progress frames and color, and keeps diagnostics on stderr.

```
agent-session-grep --db <catalog> --robot search "index rebuild" --max-items 20
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
- `outcome` — `success` or `partial`; `partial` can mean budget truncation, unmet freshness, incomplete coverage or unavailable continuation. Inspect its concrete reason (exit 10).
- `data` — command-specific payload.
- `warnings` — honest degradations (for example unknown-precision evidence).
- `page` — pagination: pass an issued `next_cursor` as `--cursor` only while more evidence is needed and `has_more` is true. Stop when the question is answered; never invent a missing token.
- `meta.generation` — index generation the result was computed against.

### Pagination loop

```text
cursor = null
while the unanswered question still needs another page:
  argv = [--db, DB, --robot, search, QUERY, --max-items, 5, --max-bytes, 8192]
  argv += SAME_EXPLICIT_FILTERS
  if cursor != null: argv += [--cursor, cursor]
  env = parse_json(run(agent-session-grep, argv))
  if not env.ok: report(env.error); break
  consume(env.data.hits, env.data.freshness, env.warnings)
  if question_supported or not env.page.has_more: break
  if env.page.next_cursor == null: report_continuation_limit(); break
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
| 7 | provider / adapter error, unsupported capability or unverified scope |
| 9 | protocol or schema incompatibility (includes cursor generation mismatch) |
| 10 | partial/unmet state; inspect freshness, coverage, truncation and warnings. `update_recovery_required` needs explicit status/recover, not automatic retry |
| 70 | internal error (bug signal) |

Valid `--help` / `--version` requests exit 0. Invalid leading/global arguments (for example an invalid `--output` or `--request-id`) still fail with `invalid_request` (exit 2); help/version do not bypass validation. In robot/json/jsonl modes valid requests are success envelopes, not bare text: help text or version string ride in `data.help_text` / `data.version` (ADR-0006).

### Commands

| command | purpose |
| --- | --- |
| `search "<query>"` | full-text search over messages; hits carry canonical `session_id`, `resume_available`, and bounded `text`; plain-text keywords only — FTS operators (`AND`/`OR`/`NEAR` and quotes) do not enable an advanced query language; tokens are literal with implicit AND, while a trailing `*` retains prefix matching (ADR-0003). Facets (all optional): `--main-only`, `--subagent-only` (mutually exclusive), `--include-sidechain` (the default), `--tool-kind` (`file`/`command`/`web`/`query`/`unknown`), `--tool-name <name>` (exact match). In the TUI, `m` cycles the sidechain facet and `k` cycles the tool-kind facet (with an empty input box) |
| `handoff "<query>"` | assemble a deterministic handoff pack (`handoff-pack/v1`) from search hits; verbatim evidence and inference stay separated, no LLM call, dry-run only; each mainline entry carries authoritative `role`/`is_sidechain` facts and the pack carries the catalog `tool_activity` list; legacy budgets `--max-evidence` (default 20), `--max-tokens` (8000), `--max-bytes` (2000000); managed defaults are above; preserve `--repo` only where supported |
| `get-session-resume <session-id>` | resolve fixed-shape read-only Resume Metadata for a canonical `ses_v1_*` id; returns nullable Provider-native Session ID and Original Working Directory, never a command or Source path |
| `get-message <message-id>` | return one message and bounded mainline neighbors; use `--session` when a shared Message belongs to multiple Sessions |
| `list <limit>` | page catalog entities in stable id order |
| `context <session-id>` | assemble one session branch with evidence spans and projected `tool_activities` |
| `get <wire-id>` | raw stored payload of one entity |
| `show <wire-id>` | structured entity view (role, text, parent, session, span) |
| `status` | catalog entity count and active generation |
| `model import --dir <bundle>` / `model status` | offline model-cache management (never networks): `import` verifies the bundle manifest and every declared SHA-256, then publishes into the local model cache (requires a `--features semantic-candle` binary); `status` reports whether the default E5 bundle is imported. Default builds stay lexical-only (bigram-hash fuzzy-lexical) |
| `providers` | report this build's provider capability matrix and per-field support; an adapter row does not establish managed background or actual host support |
| `sync --discover` | legacy unmanaged discovery scans the 12 registered provider data roots (`claude-code`, `codex`, `openclaw`, `tencent-codebuddy`, `antigravity`, `opencode`, `pi`, `hermes`, `grok-build`, `kimi-code`, `qoder`, `cline`) and sync every source matching that root's registered extension — `jsonl` for most, `json` for `hermes`/`cline`, `db` for OpenCode's SQLite store; `cursor` and `aider` have no home-relative root and are never auto-discovered, so pass their files to `sync <file>` by path; read-only on provider files; the response reports per-provider `found`/`removed` counts and scan completeness — never file paths. Managed discovery uses only persisted allowed selections, never all legacy roots; unselected explicit import cannot grant scope and pause cannot be bypassed |
| `doctor` | health: db, schema, generation, interrupted_batches, orphaned_tool_activities, orphaned_activity_memberships (prune with `index purge-activities`) |

`get`/`show` on a missing entity return exit 4 with a `not_found` error envelope (ADR-0005).

Budget flags (accepted where meaningful): `--max-items`, `--max-bytes`, `--max-messages`. Hitting a budget is reported as `outcome: "partial"` with truncation/partial metadata and exit 10 — never a silent cut. A freshness or coverage partial needs its own response, not merely a larger budget.

### Session context and evidence

```
agent-session-grep --db <catalog> --robot context ses_v1_abc123 --policy mainline
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
- `--offline` (global, placed before the command name) is a stable explicit fail-closed mode: any operation that would need the network is refused instead of degraded. Ordinary reads/indexing remain local; explicit `update check` is refused under `--offline`, while `update apply --from` remains offline. `doctor` echoes the flag in its `offline` field.

## MCP server

Run the same binary as a stdio MCP server (tools only, sequential, read-only):

```json
{
  "mcpServers": {
    "agent-session-grep": {
      "command": "agent-session-grep",
      "args": ["--db", "<catalog>", "mcp"]
    }
  }
}
```

| tool | when to use |
| --- | --- |
| `search_sessions` | full-text query; params: `query` (required), `limit`, `cursor`, `max_items`, `max_bytes`; optional `repo`, `providers` (OR filter over implemented, searchable rows from CLI `providers` / MCP `list_providers`, plus the `claude` alias for `claude-code`; unknown/deferred ids are rejected), `since`/`until`, `include_system`, `group_by_session`; facets `sidechain` (`include`/`main_only`/`subagent_only`), `tool_kind` (`file`/`command`/`web`/`query`/`unknown`), `tool_name`; each hit includes canonical `session_id` and availability/provenance where verified; non-default facets are echoed in `data.facets`; map a hit's `id` into `get_message.message_id` and retain its `session_id` |
| `get_session_context` | pull one session branch: `session_id` (required, canonical `ses_v1_...`), `policy` (`mainline` or `full`), `level` (`raw`/`talks`/`sessions`), `max_messages`, `max_bytes`; the response includes projected `tool_activities` for the assembled messages |
| `get_session_resume` | resolve fixed-shape Resume Metadata from a canonical `session_id`; nullable `provider_session_id` and `original_working_directory`; never returns a command or Source path |
| `get_message` | return one Message and bounded mainline neighbors; params include canonical `message_id`, optional canonical `session_id`, `around`, and budgets |
| `list_sessions` | page Session entities in stable canonical-id order with verified compact title/peek when available; this is not recency order |
| `generate_handoff` | assemble a deterministic handoff pack (`handoff-pack/v1`) for a query: search hits become evidence spans with authoritative source locators, mainline entries carry `role`/`is_sidechain` facts, and the pack carries the catalog `tool_activity` list; advertised query/provider/time/repo bounds and budgets `max_evidence`/`max_tokens`/`max_bytes` are enforced (legacy has no `repo`) and cross-boundary redaction is on by default (ADR-0009); truncation is reported as `outcome: partial` |
| `list_providers` | return the current build's capability matrix from the same source as CLI `providers`, including `id`, `variant`, maturity and ingestibility. Deferred/unsupported rows are listed but are not usable; no routine preflight |
| `get_status` | permitted catalog count, generation and repository identities; managed freshness is separate from these counts, no routine preflight |
| `doctor` | diagnose a reported catalog problem; legacy schema/generation/interrupted batches, managed availability and disclosed freshness. Health alone does not establish current sources |

- Tool results carry the payload twice: `content[0].text` (serialized) and `structuredContent` = `{ outcome, data, redaction, warnings, page }` — the same payload structure as the Robot envelope; process-level fields need not be duplicated. Consume one representation, not both. The complete legacy frame can exceed the Application payload estimate, while managed emission enforces its complete frame budget. `redaction` reports whether cross-boundary redaction touched this payload (`status: none | applied`, `redacted_count`), so a `[redacted:...]` value is never mistaken for literal transcript text.
- Business failures (bad cursor, not found) come back as `isError: true` results with `structuredContent.error.canonical_code`; malformed or invalid params are JSON-RPC errors (`-32602`).
- Cursors in legacy mode are self-contained unsigned, keyless integrity-checked tokens (unkeyed BLAKE3), not signatures: they do not authenticate an issuer or prevent a caller from forging a new digest. A `page.next_cursor` from one `search_sessions` call works in a later call — even across server restarts — only while the contract, query/sort/result-set binding, index generation, and TTL remain valid. Treat the token as opaque, not as authorization.
- Requests execute sequentially; `notifications/cancelled` remains a best-effort no-op. Managed request deadline enforcement is separate from this notification; it does not imply host-rendered delivery or suspension bounds.

## Cautions

- Source/read boundary: provider transcripts remain read-only. Explicit `sync`, `ingest`, and `index` operations write the local catalog; search/context and Resume Metadata reads do not acquire the catalog writer lease. Managed reads may write disposable continuation/control request state without importing sources. The MCP server opens only the `--db` store given at startup; it exposes no arbitrary file read, no SQL, no command execution.
- Two-ID contract: canonical `session_id` (`ses_v1_...`) is the catalog identity used by every tool; the Provider-native Session ID is Resume Metadata obtainable only via `get-session-resume` / `get_session_resume`. Never treat the native ID as canonical or vice versa.
- `get-session-resume` / `get_session_resume` return structured Resume Metadata only, never a command. In a legacy unmanaged catalog, for an authorized continuation CLI `resume <session-id>` previews the provider command, working directory, and permission mode. Inspect that preview and obtain explicit user approval before `resume <session-id> --yes`. First use forces a preview even with `--yes`; execution needs a subsequent explicit request. The CLI can then launch the provider with an argument vector, not shell interpolation; this execution capability is not an MCP tool. A preview does not launch the provider but can record the first-use marker in the local data root. Managed executable resume currently returns `capability_not_supported`; use explicit metadata only, never substitute a native ID for a canonical one.
- Legacy cursor lifecycle: cursors expire after 15 minutes and die whenever new data is ingested (generation change). On `cursor_expired`, `cursor_invalid`, or `generation_mismatch`, do not retry the token — re-issue the query from page 1. Cursors are also result-set-bound: a `search` cursor only works for `search`, a `list` cursor for `list`, and a `list_sessions` cursor for `list_sessions`.
- Never parse human-mode output (the default without `--robot`); its wording can change at any time. Machine consumption is `--robot`, `--output json` / `--output jsonl`, or MCP only.
