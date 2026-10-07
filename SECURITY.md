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
Open a [GitHub Security Advisory](https://github.com/Lain-in-coding/agent-session-grep/security/advisories/new)
or email the maintainers directly. You can expect:

- An acknowledgement within 3 business days.
- A severity assessment and fix timeline within 10 business days.

## Boundaries and guarantees

| Boundary | Behavior |
|---|---|
| Human CLI / TUI | Local output. Session content is shown unredacted (ADR-0004). |
| Robot JSON/JSONL, MCP, HTTP API, Web UI, Handoff Pack | Cross-boundary outputs. Secret-shaped values and secret-named JSON fields are redacted with `[redacted:<kind>]` markers (ADR-0009). The ruleset detects eleven kinds: `aws_access_key`, `aws_secret_key`, `github_token`, `gitlab_token`, `slack_token`, `google_api_key`, `stripe_key`, `api_key` (OpenAI/Anthropic/xAI), `bearer_token`, `jwt`, and `private_key`. |
| HTTP serve | Loopback-only (Host check), random bearer token per invocation, no TLS, GET-only. The token is printed in the URL **fragment** (`/#token=…`), which browsers never send to a server, so it stays out of request logs and `Referer` headers; the page moves it into an `Authorization: Bearer` header and strips it from the visible URL. Do not expose the port to a network. |
| Offline mode | The default build has no HTTP client dependency and the only socket is serve's loopback `TcpListener` (static test + CI step). No shipped capability requires the network, so the global `--offline` flag currently rejects nothing — it is a stable, explicitly reported mode (`doctor` and `hook` echo it) backed by a fail-closed gate that any future network-requiring capability must pass (`capability_not_supported`). |
| Provider transcripts | Read-only. Real user session data is never modified, uploaded, or committed. |

Redaction is a conservative, pattern-based ruleset: the shared detector lives in
`crates/agent-session-grep-ports/src/redact.rs` (ruleset `v1.1`), and
`crates/agent-session-grep-cli/src/redaction.rs` applies it to boundary
payloads including secret-named JSON fields. Only high-confidence, structured
formats are matched, so it is not a substitute for secret hygiene: treat any
transcript content as potentially sensitive, and do not rely on redaction for
secrets whose format is not covered by the ruleset.

Two scope limits are deliberate and worth knowing before you rely on the
key-name signal:

- **Key-name redaction covers string values only.** A JSON number or boolean
  under a secret-looking key is passed through unchanged, because a number
  cannot carry a secret shape while several contract fields *are* numeric
  counters whose names contain a secret-looking fragment (`max_tokens` /
  `used_tokens` in `handoff-pack/v1`, published as integers). Blanking those
  emitted a string where the schema promises an integer and destroyed the
  budget accounting the pack exists to report. Secret-named arrays and objects
  are still recursed into, not trusted.
- **Absolute paths are not secrets to this ruleset.** There is no path rule, so
  a path that crosses a machine boundary is emitted verbatim, OS account name
  included. Two routes do this today: `original_working_directory`, which
  `resume` needs in order to work, and `config paths`, which reports the
  platform config/data/cache/logs locations under the user's home directory.
  `source_path` and `transcript_path` are omitted from the resume response shape
  by design, and `doctor` carries no paths at all. A path privacy mode is an
  open threat-model decision, recorded with its fact basis in
  `docs/security/THREAT-MODEL.md` §7.1; until it is implemented and signed, the
  behaviour above is what ships.
- **The resume preview refuses rather than guesses.** The preview `command`
  string interpolates transcript-supplied values (the recorded working directory
  and the provider session id), so those values are quoted, and the whole string
  is withheld (`command: null`) when a value contains a character that can still
  escape or expand inside double quotes in cmd.exe, PowerShell or a POSIX shell.
  `working_directory` is still reported structurally, and `resume --yes` never
  goes through a shell.

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
