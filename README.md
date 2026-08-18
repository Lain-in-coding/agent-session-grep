# agent-session-grep

**Local-first search engine over AI coding-agent session history.**

`agent-session-grep` (CLI alias `asg`) normalizes heterogeneous provider
transcripts into a canonical domain model with stable identity and nonlinear
message graphs, then serves full-text retrieval, resume, and handoff through
CLI, MCP, Robot, TUI, and loopback Web UI surfaces — all sharing one
Application ADT.

**Release status:** `0.1.0` is the first public release, matching the Cargo
workspace version. Provider adapters are Experimental maturity and the optional
semantic backend carries no quality claim — see
[`docs/product/PROVIDER-MATURITY-MATRIX.md`](docs/product/PROVIDER-MATURITY-MATRIX.md).
Release archives are built from source; no signed or notarized binaries are
published yet.

## Why?

Every AI coding agent (Claude Code, Codex, Grok, Pi, …) writes its session
history in a different format, in a different local directory. When you need
to find "why did we do that three weeks ago?" or "what error did we hit in
that refactor?", you're stuck grepping raw JSONL files that don't share a
schema. `agent-session-grep` solves this by:

1. **Discovering** transcripts across multiple provider directories
2. **Normalizing** them into a canonical model (Message, Session, Placement)
3. **Indexing** for fast full-text search (FTS5 with CJK bigram support)
4. **Serving** search/resume/handoff through a unified contract

## Quickstart

Install from a repository checkout. The installers build the release binary and
install both `agent-session-grep` and `asg`; they print a PATH hint but do not
edit PATH for you.

Windows (PowerShell 7+):

```powershell
pwsh -File scripts/install/install.ps1
$env:PATH = "$env:LOCALAPPDATA\agent-session-grep\bin;$env:PATH"
agent-session-grep --version
asg --version
```

Linux or macOS:

```bash
bash scripts/install/install.sh
export PATH="${XDG_BIN_HOME:-$HOME/.local/bin}:$PATH"
agent-session-grep --version
asg --version
```

Then use either command name. Every data command needs the store path
(`--db`); run `asg config paths` to see the default data location on your
platform:

```bash
# Index your Claude Code + Codex sessions
asg --db <db-path> sync --discover

# Search across all providers
asg --db <db-path> search "authentication refactor"

# Get session context
asg --db <db-path> context <session-id>

# Preview the resume command for a session (dry-run; --yes to execute)
asg --db <db-path> resume <session-id>

# Generate a handoff pack for another agent
asg --db <db-path> handoff "how did we configure the database?"
```

Retrieval is lexical by default (FTS5 with CJK bigram support); the default
vector mode is an honest bigram-hash fuzzy-lexical matcher, not a semantic
model. An optional local semantic backend (Candle + multilingual-e5-small)
exists behind the `semantic-candle` cargo feature — off by default and
offline-only (`asg model import --dir <bundle>` / `asg model status`).

See [Install and upgrade](docs/operations/INSTALL-AND-UPGRADE.md) for custom
prefixes, persistent PATH setup, upgrades, and safe uninstall.

## Providers

Currently implemented (14/16 planned; 2 deferred — no transcript evidence):

| Provider | Status | Format |
|---|---|---|
| Claude Code | Experimental | JSONL (`type:user/assistant`, `sessionId`/`uuid`/`parentUuid`) |
| Codex CLI | Experimental | rollout JSONL (`response_item`/`message`) |
| Grok Build | Experimental | ACP `updates.jsonl` (`session/update` stream) |
| Antigravity | Experimental | transcript JSONL (`brain/<uuid>/.system_generated/logs`) |
| OpenCode | Experimental | SQLite `opencode.db` (session/message/part, read-only) |
| Pi | Experimental | session JSONL (`type:session/message`) |
| Hermes | Experimental | `session_<id>.json` (session_id/messages) |
| Cursor | Experimental | `state.vscdb` SQLite KV (`chatdata`/`prompts`) |
| Kimi Code | Experimental | wire.jsonl (`context.append_message`) |
| OpenClaw | Experimental | v3 JSONL header + message records |
| Qoder | Experimental | JSONL (`session_meta` + `type:user/assistant`) |
| Tencent CodeBuddy | Experimental | OpenAI-style JSONL (`role`/`content`/`sessionId`) |
| Cline | Experimental | JSON (`api_conversation_history.json`) |
| Aider | Experimental | Markdown chat history (`#### ` user prompts) |
| DeepSeek Harness | Deferred | — (no transcript evidence yet) |
| ZCode | Deferred | — (no transcript evidence yet) |

See [Provider Maturity Matrix](docs/product/PROVIDER-MATURITY-MATRIX.md) for
the full 16-provider roadmap and capability details.

## Architecture

```
domain ← ports ← application ← adapters
```

- **domain**: canonical entities (Message, Session, StableId, Placement)
- **ports**: trait contracts (CatalogStore, SearchIndex, ProviderAdapter)
- **application**: use cases (Search, Context, Handoff, Resume)
- **adapters**: concrete implementations (SQLite, Claude/Codex/Grok/Pi providers)

### Key design decisions

- **Stable Identity**: BLAKE3-based content-addressed IDs that survive file
  moves, renames, and incremental appends
- **Evidence-first**: every search hit carries a source span for verification
- **Privacy**: zero telemetry, zero upload, offline by default; the global
  `--offline` flag refuses any network-requiring capability (fail-closed),
  and the default build has no HTTP client dependency (verified by a static
  network-egress test and the security-audit workflow); cross-boundary
  outputs (Robot/MCP/Web/Handoff) are redacted by default (ADR-0009)
- **Honest maturity**: providers are graded certified/GA/beta/experimental/
  unsupported — never inflated

## License

MIT OR Apache-2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Community provider adapters follow
the Provider Adapter Protocol (versioned external process, manifest-declared,
read-only, no network by default).

Release history is tracked in [CHANGELOG.md](CHANGELOG.md); security
boundaries and the vulnerability reporting process are in
[SECURITY.md](SECURITY.md).
