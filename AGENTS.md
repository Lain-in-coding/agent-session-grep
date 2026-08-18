# agent-session-grep Repository Onboarding

Orientation for AI coding agents working in this repository. `CLAUDE.md` holds
the agent-specific rules and `CONTRIBUTING.md` holds the full commit and
collaboration standards; this file adds the repository map and the reading order
that make those rules actionable. Where they overlap, `CLAUDE.md` and
`CONTRIBUTING.md` win.

## What this project is

`agent-session-grep` (CLI alias `asg`) is a local-first, CLI-first search engine
over AI coding-agent session history. It discovers provider transcripts on disk,
normalizes them into a canonical domain model with stable content-derived
identity and nonlinear message graphs, and serves retrieval, session context,
resume, and handoff through CLI, Robot JSON/JSONL, MCP, TUI, and loopback Web UI
surfaces that all share one Application ADT.

It is a read-only consumer of transcripts: no telemetry, no upload, offline by
default.

## Architecture

The workspace is hexagonal. Dependencies point one way only:

```
domain ← ports ← application ← adapters ← cli
```

| Layer | Crate(s) | Responsibility |
|---|---|---|
| domain | `agent-session-grep-domain` | Canonical entities and invariants (Message, Session, SourceDocument, Placement, StableId, mainline selection). No I/O, no provider types. |
| ports | `agent-session-grep-ports` | Trait contracts the application depends on (`SourceDiscovery`, `CatalogStore`, `ContextGraphStore`, `SearchIndex`, `SemanticIndex`, `ProviderAdapter`, …). |
| application | `agent-session-grep-application` | Use cases over the ports: search, session context, activity facets, cursors, response budget, hybrid fusion, resume, handoff pack. |
| adapters | `agent-session-grep-adapters-sqlite`, `agent-session-grep-provider-*` | Concrete port implementations: the SQLite catalog + FTS projection, and one crate per provider transcript format. |
| cli | `agent-session-grep-cli` | Composition root and every entry point: human CLI, Robot modes, MCP stdio server, TUI, `serve` loopback HTTP + Web UI, hooks, redaction. |

`agent-session-grep-testkit` provides shared test helpers and is a dev
dependency only.

Rules that follow from the layering:

- Provider-native fields never leak past an adapter boundary; adapters reduce a
  transcript to canonical events.
- Application code depends on ports, never on a concrete adapter.
- Every surface goes through the same Application ADT, so a behavior change
  belongs in `application`, not in one entry point.

## Quality gate

Run these from the repository root and confirm green before proposing a commit:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The Python evidence, release, and installer harnesses are stdlib-only
`unittest`. Run the suite for whichever directory you touched:

```
python -m unittest discover -s scripts -p "test_*.py"
python -m unittest discover -s scripts/evidence -p "test_*.py"
python -m unittest discover -s scripts/release -p "test_*.py"
```

## Commit and collaboration

- Conventional Commits: `type(scope): subject`, subject ≤ 50 characters,
  imperative mood, no trailing period. One logical change per commit.
- Never run `git commit` or `git push` unless the user explicitly asks. Stage
  specific files; never `git add .` blindly.
- Feature branch → pull request into `main`. Do not push to `main` and do not
  merge pull requests; merging is the repository owner's decision.
- Commits are authored by the repository owner only: no AI co-author trailer,
  no "Generated with ..." footer, no command transcript in the message.
- Do not amend, squash, or rebase pushed commits unless explicitly asked.
- Destructive commands (`git reset --hard`, `git clean -fd`, `git push -f`,
  `rm -rf`) are prohibited unless the user gives the exact command in the same
  message and states they understand the consequences.

## Privacy rules

- Provider transcripts are read-only. Never modify, upload, or commit a real
  user's session data.
- Keep real personal paths, hostnames, and identities out of code, tests,
  fixtures, docs, commit messages, and pull request text. Test fixtures are
  synthetic or irreversibly redacted, with provenance documented.
- Never commit secrets. `.env`, `*.pem`, `*.key`, and `credentials*` are
  gitignored; keep it that way.
- Do not add telemetry, uploads, or unrequested network access. The default
  build has no HTTP client dependency and the only socket is `serve`'s loopback
  listener; a static test and the `security-audit` workflow enforce this.
- Human CLI/TUI output is local and unredacted by design (ADR-0004);
  cross-boundary output (Robot, MCP, HTTP, Web UI, handoff pack) is redacted by
  default (ADR-0009). Do not move content across that boundary without going
  through the redaction path.

## Authority order

When sources disagree, prefer in this order:

1. The user's current request and the repository-level instruction files
   (`CLAUDE.md`, `CONTRIBUTING.md`, this file).
2. Formal records: ADRs under `docs/adr/`, RFCs under `docs/architecture/`, the
   contract under `docs/contracts/`, and the JSON Schemas under `schemas/`.
3. Executable evidence: tests, CI results, and the harnesses under `scripts/`.
4. Git history and `CHANGELOG.md`, for historical context only.

## Where to read next

- `README.md` — product overview, install, provider table.
- `CONTEXT.md` — canonical glossary; use its terms and avoid the listed
  synonyms.
- `docs/PROVIDER-ADAPTER-CONTRIBUTOR-GUIDE.md` — the contract, evidence, and
  privacy requirements for adding a provider adapter.
- `docs/contracts/CONTRACT-cli-robot-mcp-draft.md` — the shared CLI / Robot /
  MCP contract, including exit codes and error envelopes.
- `docs/architecture/RFC-0001-canonical-model-and-stable-id.md` and
  `RFC-0002-provider-adapter-contract.md` — canonical model and adapter
  contract.
- `SECURITY.md` — boundaries, guarantees, and vulnerability reporting.
