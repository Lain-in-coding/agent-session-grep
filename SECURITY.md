# Security Policy

agent-session-grep reads AI coding-agent session transcripts and surfaces
their content through search, context assembly, resume, and handoff
features. The security posture below applies to every boundary that emits
that content.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Planned first public series; not released yet |
| Published releases | None |

## Reporting a vulnerability

Please report security issues privately — do not open a public issue.
Open a [GitHub Security Advisory](https://github.com/qin-devs/agent-session-grep/security/advisories/new)
or email the maintainers directly. You can expect:

- An acknowledgement within 3 business days.
- A severity assessment and fix timeline within 10 business days.

## Boundaries and guarantees

| Boundary | Behavior |
|---|---|
| Human CLI / TUI | Local output. Session content is shown unredacted (ADR-0004). |
| Robot JSON/JSONL, MCP, HTTP API, Web UI, Handoff Pack | Cross-boundary outputs. Secret-shaped values (AWS keys, GitHub PATs, OpenAI/Anthropic/xAI keys, Bearer tokens, PEM private keys) and secret-named JSON fields are redacted with `[redacted:...]` markers (ADR-0009). |
| HTTP serve | Loopback-only (Host check), random bearer token per invocation, no TLS, GET-only. Do not expose the port to a network. |
| Offline mode | Global `--offline` flag rejects any network-requiring capability (`capability_not_supported`); the default build has no HTTP client dependency and the only socket is serve's loopback `TcpListener` (static test + CI step). |
| Provider transcripts | Read-only. Real user session data is never modified, uploaded, or committed. |

Redaction is a conservative, pattern-based ruleset (see
`crates/agent-session-grep-cli/src/redaction.rs`). It is not a substitute for
secret hygiene: treat any transcript content as potentially sensitive, and do
not rely on redaction for secrets whose format is not covered by the ruleset.

## Dependencies

Pull-request checks run `cargo deny check`, while
`.github/workflows/security-audit.yml` runs `cargo deny check` and
`cargo audit --file Cargo.lock` weekly and on manual dispatch. Audit tool
versions and their install dependency graphs are pinned, the committed lockfile
is verified with `cargo metadata --locked`, and the workflow has read-only
repository permissions with checkout credential persistence disabled. It has no
step that uploads repository source or audit artifacts.

Dependabot checks Cargo and GitHub Actions dependencies weekly. Keep
`Cargo.lock` committed for all releases. These controls do not generate or
attest an SBOM, third-party license bundle, provenance, signature, or
notarization; those remain separate release and governance work.
