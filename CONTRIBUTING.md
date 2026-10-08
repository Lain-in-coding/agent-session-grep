# Contributing to agent-session-grep

Thanks for your interest in contributing. This document defines the commit and
collaboration standards for this repository. They are strict on purpose: the
project is local-first and privacy-sensitive, so keeping secrets and personal
data out of history is the highest priority.

The sole authority for future development and releases is
[Lain-in-coding/agent-session-grep][canonical]. Open branches and PRs
there; an old checkout or export is not a second product authority.
Historical import snapshots remain immutable provenance, not current
whole-tree manifests. These are repository rules informed by public
practices, not claims about company-wide internal standards.

[canonical]: https://github.com/Lain-in-coding/agent-session-grep

## Contribution entry points

- Provider adapters: [Provider Adapter Contributor Guide](docs/PROVIDER-ADAPTER-CONTRIBUTOR-GUIDE.md)
- Bugs: [bug report form](.github/ISSUE_TEMPLATE/bug-report.yml)
- Ideas: [feature request form](.github/ISSUE_TEMPLATE/feature-request.yml)
- Pull requests: [pull request template](.github/pull_request_template.md)

The adapter guide adds provider-specific evidence and privacy requirements; the
commit, collaboration, and quality standards below remain in force.

## Commit messages (Conventional Commits)

1. Format: `type(scope): subject`, with exactly one space after the colon.
   The only types are `feat`, `fix`, `docs`, `refactor`, `test`, `chore`,
   `ci`, and `perf`. Scope and subject must both be nonempty. Use a
   lower-case scope matching `[a-z][a-z0-9]*(?:[-./_][a-z0-9]+)*`, such as
   `search` or `provider-codex`; scopes are not a fixed list of crates.
2. The **complete header** is at most **50 Unicode code points**, including
   type, scope, punctuation, spaces, and subject; not just the subject.
   Use an English subject in imperative mood ("add", not "added"), with no
   trailing period. Unicode identifiers and names are allowed in messages.
3. Leave a blank line after the header, then give a nonempty, substantive
   **why** paragraph in English. Explain the reason, not just the diff.
   Chinese may supplement the core explanation. Every body line, including
   footers and URLs, is at most **72 Unicode code points**. Empty bodies,
   footer-only text, and unchanged template placeholders are invalid.
4. One logical change per commit (atomic commits). Do not bundle unrelated
   changes. Syntax checks cannot prove meaningful rationale, English
   wording, or atomicity; human review is required. Do not substitute an
   unreliable language detector or an ASCII-only message rule.
5. Never `git add .` blindly. Stage specific files so unrelated changes do
   not slip in.

Control characters, hidden skip-CI directives, and fixup/squash prefixes
are not permitted. Merge, rollback, and version-only commits have no
exemption. A breaking change keeps the same scoped header and includes a
`BREAKING CHANGE:` footer explaining impact and migration, in addition to
its why paragraph. A rollback uses an allowed type with its reason and
target SHA; there is no extra `revert` type.

Example message (the same format applies to a proposed merge message):

```text
fix(search): preserve cursor boundaries

Stable page boundaries prevent duplicate results when users resume a
search after new sessions are indexed.
```

## Preventing secret and data leaks (highest priority)

- Build artifacts (`target/`), dependencies, caches, and local databases
  (including sidecar files) never enter the repository.
- Keep `.env`, `*.pem`, `*.key`, `credentials*`, and `.mcp.json` gitignored.
  Secrets go through environment variables. Only commit an `.env.example`
  template, never real values.
- Keep real transcripts, private personal paths, private hostnames, and
  unrelated personal data out of code, tests, fixtures, docs, logs, commit
  messages, and PR text. This does not prohibit genuine author/committer
  metadata, human co-author credit, or required copyright/license notices.
- Use synthetic or irreversibly redacted fixtures with documented
  provenance, never real sessions or copied provider databases. Generate
  synthetic credential-shaped test values at runtime; do not hardcode
  token-shaped examples into repository files or history.
- Before pushing or publishing, run both path/privacy and credential
  gates. Scan the exact tracked candidate tree **and separately all
  introduced commits**, intermediate blobs (even if later deleted), commit
  messages, PR title/body, and proposed merge message. A clean final tree
  or valid PR title cannot hide an earlier bad commit or leaked message.
- Keep existing path-scanner rules and allowlists intact. Use the pinned
  standalone Gitleaks 8.30.1 wrapper with checksummed provisioning, trusted
  config, controlled ignores, no inline allow comments or baseline
  suppression. Scanning is offline; never test tokens against a service.
- Capture raw scanner output privately, even when redacted. Share only
  reviewed safe rule/count/relative-location summaries, never raw matches,
  personal details, reports, or command transcripts. Tool errors, missing
  history/base, incomplete pagination, or incomplete coverage are failures,
  not clean scans. Review unsupported binary/archive/decoding coverage;
  unreviewed exclusions block publication. Scanners do not prove that all
  secrets or personal data are absent.

Existing formal history and publication surfaces also need review before
initial public cutover or visibility changes. Clean introduced history does
not certify old repositories or erase historical debt; do not rewrite old
history or widen allowlists to conceal it.

## Collaboration workflow

1. Work on a feature branch in the canonical repository and open a pull
   request into `main`. Do not push directly to `main`.
2. PR titles follow the same scoped English full-header 50-code-point rule.
   PR bodies need a substantive English why, risks, and verification, with
   lines at most 72 code points. Chinese may supplement them; discussion
   may be Chinese. Replace template prompts, not just check boxes.
3. Mandatory checks must actually succeed for the current candidate SHA.
   Record the PR, base/head SHAs, rationale, risks, commands/results, and
   check links. Failed, cancelled, skipped, missing, or not-started checks
   are not success. A green title check does not validate commit history.
4. The human owner must explicitly accept **each PR at its current SHA**
   after semantic, attribution, privacy, and verification review. This is
   the documented solo-maintainer exception, including owner-authored
   PRs: it is **not two-person review**. Do not invent a second reviewer or
   a GitHub self-APPROVED review. Task consent is not merge authorization;
   AI must not autonomously approve, merge, impersonate a reviewer, or
   waive checks. New commits or material PR metadata edits invalidate
   prior acceptance; refresh checks and human acceptance before merging.
5. Use an ordinary merge commit, preserving reviewed atomic commits,
   their SHAs, and genuine authors. No default squash/rebase. Validate the
   proposed merge message under the same scoped English header, 50/72,
   and substantive why rules; GitHub's default merge text is not exempt.
   Recheck the current base/head, checks, and acceptance before any
   separately authorized merge, then verify the actual merge metadata.
6. Do not amend, squash, or rebase commits that have already been pushed,
   unless explicitly requested. Fixes and rollbacks use newly reviewed
   PRs under the same gates; no historical rewriting to hide violations.
7. Run the local quality gate before committing:
   `cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`,
   and `cargo test --workspace`, plus applicable feature/helper tests.

### Genuine attribution

Owner-delegated work uses the confirmed, authorized owner Git identity.
External contributors retain real authorship, source/license provenance,
and genuine human co-authors. Already-authorized bots keep their bot
identity and pass the same gates; this policy installs no bots and expands
no permissions. Resolve author and committer separately; public/noreply
identities are allowed, and private contact details are not required.
Attribution grants no write or merge authority. Never invent an author, AI
co-author, generated-tool advertisement, or command transcript. Human
review must assess attribution: Git metadata cannot prove identity or
consent, and one owner email is not a substitute for contribution checks.

### Shared checks and installation status

`scripts/governance/` owns the shared Python-stdlib policy, checker tests,
path/credential wrappers, and opt-in local hook adapter. Hooks are optional
local feedback, not merge authority; never replace global or existing
hooks. The helper interfaces below are integrated by the candidate
`governance` workflow; hosted bootstrap and enforcement remain pending.
Consult each reviewed helper's `--help`. These commands do not establish
that hosted enforcement is installed.
Replace input placeholders with verified data, never untrusted shell text.

```text
python scripts/governance/check_commit.py --message-file <file>
python scripts/governance/check_commit.py --repo . --base <B> --head <H>
python scripts/governance/check_pr.py --event-file <json>
```

Use message-file mode for the proposed merge message as well. Range mode
checks every commit reachable from head but not base, including merges.
Base is the independently observed current target tip, not necessarily an
ancestor of head; both complete graphs need a common ancestor.

`check_pr.py --event-file` alone checks metadata, **not commit history**.
Add `--repo` to validate the complete introduced range. Supply independent
`--expected-base`, `--expected-head`, and numeric `--repository-id` values
to reject stale or wrong events. Add `--merge-message-file` for the exact
proposed message and `--merge-metadata-file` for its author/committer JSON.
The latter requires the message file and has this structural shape:
`{author:{name,email},committer:{name,email}}` (use valid JSON, not this
shorthand). Record the checker's output `metadata_sha256` with PR/base/head
and human acceptance. Re-run after edits and renew acceptance for changed
text, even without a new commit; a digest is not human approval.

The following examples use PowerShell continuations and variables. Supply
`$base`, `$head`, `$event`, `$repositoryId`, `$mergeMessage`, and
`$mergeMetadata` from independently verified inputs; SHAs are complete
lowercase 40-hex values. `$archive` is the verified pinned release archive,
not an installed executable. Choose `$platform` from `linux_x64`,
`windows_x64`, `darwin_x64`, or `darwin_arm64`; omission of `--platform`
uses the supported native platform. Other shells use the same arguments
with their own continuation/variable syntax. Do not auto-configure an
environment or provision tools; any environment setting is process-local
or explicitly user-opted configuration, never an automatic global change.

```powershell
python scripts/governance/check_pr.py --event-file $event `
  --repo . --expected-base $base --expected-head $head `
  --repository-id $repositoryId --merge-message-file $mergeMessage `
  --merge-metadata-file $mergeMetadata

python scripts/governance/scan_paths.py --repo . --base $base `
  --head $head --event-file $event --repository-id $repositoryId `
  --merge-message-file $mergeMessage `
  --merge-metadata-file $mergeMetadata

python scripts/governance/scan_credentials.py --repo . --base $base `
  --head $head --gitleaks-archive $archive --platform $platform `
  --event-file $event --repository-id $repositoryId `
  --merge-message-file $mergeMessage `
  --merge-metadata-file $mergeMetadata
```

The credential wrapper requires `--gitleaks-archive` and re-verifies its
pinned hash before execution; scanning never downloads or checks live
credentials. Its event and merge-file arguments are optional CLI inputs,
not implicit coverage: supply them when auditing those required surfaces.
Event base/head must match the range. Merge metadata requires a merge
message. `scan_paths.py` is the separate required public path/privacy
gate, with no archive or platform argument. It checks the exact HEAD tree
and every introduced path/blob/commit-metadata context, including private
paths added then deleted. It reuses the unchanged trusted public privacy
rules; credential scanning, safe-path validation, or a HEAD-only scan is
not a substitute. Pass the same event and merge inputs to both scanners.

Both scanners decode complete JSON keys and string values, including
identity fields, rather than scanning only selected title/body fields or
escaped raw JSON. NUL in metadata is rejected. Genuine attribution still
follows the contribution rules; decoding is not an identity blacklist.

For either scanner's separately scoped existing-history audit, use
`--whole-history` with `--head`, **without `--base`**. It covers **only the
selected head's ancestry**, NOT all refs/tags, release assets, or other
published surfaces. Outputs explicitly report `all_refs_scanned=false`
and `published_assets_scanned=false`; a pass does not complete the broader
publication audit or silently baseline old debt. Keep any applicable
metadata inputs, and archive/platform arguments for credentials only:

```powershell
python scripts/governance/scan_paths.py --repo . --whole-history `
  --head $head

python scripts/governance/scan_credentials.py --repo . --whole-history `
  --head $head --gitleaks-archive $archive --platform $platform
```

Provision only when explicitly chosen. Set `$newDirectory` to a new local
output directory. Provisioning downloads and verifies the pinned archive
and retains that archive, the binary, and its MIT license; keep the license.
Use `--archive-file $archive` instead of downloading for offline input.
Neither command below is automatic setup:

```powershell
python scripts/governance/provision_gitleaks.py `
  --output-dir $newDirectory --platform $platform

python scripts/governance/provision_gitleaks.py `
  --output-dir $newDirectory --platform $platform `
  --archive-file $archive
```

The full governance unit suite requires `GOVERNANCE_TEST_ARCHIVE` to point
to the verified archive for the native test platform. Missing input is a
failure, **not a skip**. Required suites must actually pass: any skipped
or expected-failure test rejects the run, as do failed tests, unexpected
successes, or an empty suite. There is no fixed total test count. After
opting in, set the archive in the current process and run the suite; do
not commit personal archive paths or persist settings automatically:

```powershell
$env:GOVERNANCE_TEST_ARCHIVE = $archive
python -m unittest discover -s scripts/governance -p "test_*.py" -v
```

Syntax and Git metadata cannot replace human language, meaningful why,
atomicity, or attribution review.

Ordinary PR validation uses complete checker/config tooling from the
exact base revision; candidate self-tests run in a separate read-only job
without secrets. Only when the entire base `scripts/governance/` directory
is absent may the workflow use the explicit repository variable
`GOVERNANCE_BOOTSTRAP_SHA`, containing a full immutable commit SHA. Partial
base tooling, an empty/invalid variable, or incomplete selected tooling
fails closed. Complete base tooling always wins; there is no candidate
head, branch-name, or inferred fallback.

Trusted PR validation independently reads current PR metadata through the
read-only API before and after checks. It rejects trigger/API differences
in base, head, title, or body rather than testing another revision. The
current API snapshot is frozen as the event file used by all checks and
the `metadata_sha256` binding; raw responses stay private. The complete
parsed JSON event is bound by a canonical digest before and after checks.
The final API read must match that successfully validated full-event
digest; it never overwrites the frozen event or accepts unscanned data.
No fields are excluded: identity, labels, mergeability, counters, and
timestamps all participate. Even volatile-field changes reject the run
and require another run; this deliberate sensitivity is not a bypass or
a reason to whitelist metadata fields.

The read-only token exists only in the trusted API steps, never candidate
self-tests or scanner subprocesses. These are point-in-time observations,
not an atomic lock on a later merge; the owner must still recheck current
evidence before separately authorizing it. Push validation uses the exact
before/head range without a PR API call.

Before any authorized variable setup, the human owner must explicitly
review/freeze the actual checker commit and fixture evidence during
platform rollout. This workflow does not set the variable or create
required checks. Bootstrap is installation evidence, not pre-existing protection.
The always-running aggregate requires actual success from both metadata/
privacy checks and candidate self-tests; skipped, cancelled, failed, or
missing dependencies cannot pass. Workflow/control-path changes require
explicit owner review. Repository-owned workflows alone
are not tamper-proof server enforcement. Actual successful target-repo
runs, supported required-check settings, and negative-gate evidence are
needed before claiming enforcement. Local passes and workflow files do
not prove hosted success; unavailable runners or protection remain blockers.

## Destructive operation policy

Destructive Git and filesystem commands — `git reset --hard`, `git clean -fd`,
`git push -f`, `rm -rf`, and similar — are prohibited unless the requester
gives the exact command in the same message and states they understand the
consequences.
