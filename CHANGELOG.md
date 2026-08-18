# Changelog

All notable changes to agent-session-grep are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-18

First public release. Everything below shipped in `0.1.0`.

### Added

- 16-provider capability matrix (`agent-session-grep-ports`) with deferred
  provider rows (`deepseek-harness`, `zcode`) and per-provider maturity grading.
- Provider adapters for the 14 implemented, Experimental providers:
  `claude-code`, `codex`, `grok-build`, `antigravity`, `opencode`, `pi`,
  `hermes`, `cursor`, `kimi-code`, `openclaw`, `qoder`, `tencent-codebuddy`,
  `cline`, and `aider`. Each adapter has evidence-backed synthetic fixtures;
  DeepSeek Harness and ZCode remain deferred because no transcript evidence is
  available.
- Source installers install both `agent-session-grep` and `asg`: Windows uses
  two executable copies; Unix uses a managed symlink or wrapper. Upgrade and
  uninstall are idempotent and refuse unrelated aliases.
- `handoff <query>` CLI subcommand — deterministic handoff-pack/v1 generation
  with evidence/inference separation and budget truncation.
- `resume <session-id>` CLI subcommand — dry-run by default (prints the
  provider command, original working directory, and permission mode);
  `--yes` spawns the provider in that directory. Providers whose resume
  command is unverified report `available:false` rather than a fabricated
  command.
- `search --mode lexical|semantic|hybrid` — retrieval mode selection. The
  default vector mode uses bigram hashes for fuzzy lexical matching, not a
  semantic model; hybrid combines lexical and vector rankings with RRF.
  Semantic and hybrid metrics remain informational and carry no release
  threshold or quality claim. A real local semantic backend is available
  through the optional `semantic-candle` cargo feature (off by default).
- `hook <session-start|user-prompt-submit>` CLI subcommand — Claude Code hook
  integration, disabled by default. Reads the hook payload from stdin and emits
  the `hookSpecificOutput.additionalContext` contract; nothing is injected
  unless `--enable` is passed. Injected text is redacted (ADR-0009).
- `serve --port <n>` CLI subcommand — loopback HTTP server (random bearer
  token, Host loopback check, embedded Web UI, JSON API).
- MCP tools: `search_sessions`, `get_session_context`, `get_session_resume`, `get_message`, `list_sessions`, `generate_handoff`, `list_providers`, `get_status`, and `doctor` (9 total).
- Cross-boundary output redaction (ADR-0009): Robot JSON/JSONL, MCP, HTTP API,
  Handoff Pack, and Web UI redact standalone and prose-embedded secrets
  (AWS keys, GitHub PATs, OpenAI/Anthropic/xAI keys, Bearer tokens, PEM
  private keys, secret-named JSON fields). Human CLI/TUI output stays
  unredacted (ADR-0004).
- Bounded ingestion (RFC-0002 §7): `ingest`/`sync` read every source through
  `ReadOnlySource`/`BoundedLineReader` with per-format caps (JSONL 8 MiB per
  record, JSON-family 32 MiB, SQLite 128 MiB); an oversized source or record
  fails closed (`SourceTooLarge`/`RecordTooLarge`) instead of loading the whole
  file into memory.
- Global `--offline` flag: fails closed on any future network-dependent
  capability (`capability_not_supported`, exit 7); `doctor`/`hook` report the
  flag. The default build carries no HTTP client dependency and the only socket
  is `serve`'s loopback listener, enforced by `tests/network_egress.rs` and a
  `security-audit` CI step.
- `hook` gains `--provider` (repeatable) and `--decay-days` filters, wired into
  the same `SearchFilters` the CLI and MCP use.
- Session metadata search (schema v11 `session_fts`): search by resolved
  provider session id, pair-observed original working directory, or the first
  user request in a session, without indexing absolute source paths.
- `serve` hardening: bounded worker pool, request size limits, Host/Origin
  loopback checks, forwarded-header rejection, a POST CSRF gate, and an
  `/api/projection/search` alias shared with the consistency harness.
- `tui --snapshot-json <query>`: headless structural search projection over the
  same Application path, so the release harness needs no terminal automation.
- 12 additional provider golden fixtures (grok, antigravity, opencode, pi,
  hermes, cursor, kimi, openclaw, qoder, codebuddy, cline, aider): synthetic
  transcript plus `PROVENANCE.md`, pinned canonical output, span round-trip,
  and a read-only checksum regression, alongside the existing Claude/Codex
  golden evidence.
- Resume execution contract: the first run forces a preview acknowledgement
  before any real spawn, the provider binary is preflighted, and a drift test
  keeps the capability matrix and the resume command builder aligned.
- `scripts/evidence/privacy_scan.py`: scans tracked text for personal or
  machine-specific absolute paths, alongside
  `docs/operations/PUBLIC-HISTORY-SCRUB.md` for the history decision.
- `scripts/verify-release.py` expanded to 10 checks (binary/version, sync,
  lexical search, get, context, resume metadata and dry-run, deterministic
  handoff, semantic/hybrid effective modes, hook default-off, provider matrix).
- `scripts/rehearsal/compare_entrypoints.py`: the five-entry-point consistency
  harness now directly compares all five surfaces (CLI, MCP, Robot, Web, TUI)
  for the canonical search operation — Web launches a real loopback `serve`
  process and TUI drives `--snapshot-json`. An unimplemented entry point fails
  the harness instead of being recorded as a skip.
- Optional local semantic backend (`semantic-candle` cargo feature, default
  off): Candle 0.10 + pinned
  `intfloat-multilingual-e5-small@614241f6-candle-f32-meanpool-l2-qpass-v1`
  (384 dims, mean pooling, L2, `query:`/`passage:` prefixes). `model import
  --dir <bundle>` verifies every declared SHA-256 and atomically publishes the
  bundle into the local model cache (never downloads); `model status` reports
  whether the default E5 bundle is imported. Default builds stay
  bigram-hash / lexical-only, and missing weights keep the explicit
  `lexical_fallback` behavior. See `docs/operations/SEMANTIC-MODEL-BUNDLE.md`.
- Handoff packs project authoritative per-message facts: each mainline entry
  now carries `role` and `is_sidechain` (missing facts render `unknown` /
  `false`, never fabricated), and the pack carries the catalog `tool_activity`
  list for its hit messages (`handoff-pack/v1` schema updated).
- TUI search facet controls: `m` cycles the sidechain facet
  (include → main-only → subagent-only) and `k` cycles the tool-kind facet
  (any → file → command → web → query → unknown) with an empty input,
  reissuing the search through the same `SearchFacets` contract as CLI/MCP.
- Context responses (`context` CLI, `get_session_context` MCP) project
  `tool_activities` for the assembled messages via the ContextGraphStore batch
  read; empty when nothing is stored, never fabricated.
- Provider Beta readiness ledger (`docs/product/PROVIDER-BETA-READINESS.md`):
  per-provider local vs external Beta blockers, so no provider is promoted
  from code existence alone.

### Fixed

- serve query-string routing: `/api/search?q=...` no longer 404s.
- Smoke scripts assert the actual 9 MCP tools (was 7 after the provider wave;
  `generate_handoff` brought it to 9).
- `verify-release.py` runs with `--db` and a committed gate fixture.
- Redaction now covers secrets embedded inside prose (previously only
  whole-string secrets were matched).

### Release scope

- CLI, Robot JSON protocol, MCP server, TUI, and Web UI adapters sharing one
  Application ADT. The cross-entry consistency harness reports `consistent`
  across all five; the three-platform clean-environment rehearsal is not
  complete (macOS was not run).
- Session search over the implemented provider set (lexical FTS5 plus ranked
  fuzzy-lexical retrieval), resume metadata extraction, and handoff packs.
- Installer scripts for Windows (PowerShell) and Unix (Bash), release
  rehearsal automation, and an evidence-backed open-source gate manifest.
- Core Beta evidence harness: lexical recall at 10 = 1.00 and parse loss =
  0.00 on the committed synthetic gate fixture.
