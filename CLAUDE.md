# CLAUDE.md

Instructions for AI coding agents working in this repository. See
`CONTRIBUTING.md` for the full commit and collaboration standards; the rules
below are the agent-specific reminders that matter most.

## Git

- **Never `git commit` or `git push` without an explicit user request.**
  You may advise the user, but only act when asked to commit or push.
- Follow `CONTRIBUTING.md`: `type(scope): subject`, exactly one space after
  the colon; types `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`,
  `perf`. Scope and subject are required; use the documented lower-case
  scope convention. The complete header is at most 50 Unicode code points,
  not just the subject. Use imperative English and no trailing period.
- Leave a blank line, then a substantive English why; all body lines are
  at most 72 code points. Chinese may supplement. Unicode identifiers and
  names are allowed; no ASCII ban or unreliable language detector. Empty,
  footer-only, or placeholder rationale, control characters, and hidden
  skip-CI/fixup bypasses are invalid; merges have no exemption.
- One logical change per commit. Stage specific files, never `git add .`
  blindly. Work in `Lain-in-coding/agent-session-grep`, the sole future
  development/release authority. Feature branch -> PR into `main`; no
  direct main push, dual export authority, or autonomous AI merge.
- Each PR needs explicit human-owner acceptance for its current SHA and
  actual mandatory check success, with rationale, risks, and verification
  recorded. The solo-maintainer exception also covers owner-authored PRs;
  it is not two-person review or a GitHub self-APPROVED review. Do not
  invent reviewers. Task consent is not merge approval. New commits or
  material PR metadata edits invalidate prior acceptance; rerun checks and
  obtain fresh acceptance. PR titles/bodies follow the same 50/72 rules.
- Use an ordinary merge preserving atomic commits, SHAs, and authors, not
  default squash/rebase. The proposed merge message needs the same scoped
  English header and substantive why. Recheck base/head and approvals;
  GitHub's default merge text is not exempt. No autonomous approval, merge,
  or gate waiver by AI.
- Owner-delegated work uses the confirmed, authorized owner identity.
  Preserve external authors, genuine human co-authors, required license
  attribution, and already-authorized bot identities. Check author and
  committer separately; attribution gives no write/merge authority. Do not
  invent AI co-authors, generated-tool advertisements, or transcripts.
  Human semantic/attribution review cannot be proved by syntax or Git
  metadata, nor replaced by checking one owner email.
- Do not amend, squash, or rebase pushed commits unless explicitly asked.
- Destructive commands (`git reset --hard`, `git clean -fd`, `git push -f`,
  `rm -rf`) are prohibited unless the user gives the exact command in the
  same message and states they understand the consequences.

## Privacy and secrets

- Keep private personal paths, private hostnames, and unrelated personal
  data out of code, tests, fixtures, docs, logs, commit messages, and PR
  text. Genuine author/committer metadata, human co-author credit, and
  required copyright/license attribution are not prohibited.
- Use synthetic or irreversibly redacted fixtures with provenance.
  Generate synthetic credential-shaped test values at runtime; never
  hardcode token-shaped examples or use real sessions.
- Path/privacy and credential gates separately cover the current tree
  and all introduced commits/blobs/messages, PR title/body, and proposed
  merge message. A good title cannot hide an invalid earlier commit.
  Preserve scanner rules and immutable import snapshots; keep raw
  findings private and share only reviewed safe summaries.
- Never commit secrets. `.env`, `*.pem`, `*.key`, `credentials*`, and `.mcp.json`
  are gitignored; keep it that way.
- Provider source transcripts are read-only. Never modify, upload, or commit a
  real user's session data.

## Quality gate

Before proposing a commit, run and confirm green:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run applicable helper/feature tests and the shared `scripts/governance/`
interfaces documented in `CONTRIBUTING.md`. Governance tests require
`GOVERNANCE_TEST_ARCHIVE` pointing to the verified native-platform
archive; missing input fails, not skips. Configure only the process or
explicitly user-opted settings; do not auto-provision tools or persist
configuration. Local hooks are opt-in; do not replace global or
existing hooks. Bootstrap requires an explicitly
owner-reviewed frozen checker revision; candidate tests are not trusted
server enforcement. Missing tooling/checks/protection are blockers. Do
not claim hosted success or enforcement from local passes or YAML alone.

## Working style

- Read the relevant files before changing them. Make the smallest change that
  satisfies the task; do not add speculative abstractions or fallbacks.
- Fix root causes rather than suppressing symptoms.
