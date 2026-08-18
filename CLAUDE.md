# CLAUDE.md

Instructions for AI coding agents working in this repository. See
`CONTRIBUTING.md` for the full commit and collaboration standards; the rules
below are the agent-specific reminders that matter most.

## Git

- **Never `git commit` or `git push` without an explicit user request.** You
  may advise the user to commit or push, but do not run these commands on your
  own. Only act when the user says "commit" or "push".
- Commits are authored by the repository owner only. Never add an AI
  co-author, a "Generated with ..." footer, or a command transcript to a commit
  message.
- Follow Conventional Commits (`type(scope): subject`). One logical change per
  commit. Stage specific files; never `git add .` blindly.
- Feature branch → pull request into `main`. Do not push to `main` directly and
  do not merge pull requests; merging is the owner's decision.
- Do not amend, squash, or rebase pushed commits unless explicitly asked.
- Destructive commands (`git reset --hard`, `git clean -fd`, `git push -f`,
  `rm -rf`) are prohibited unless the user gives the exact command in the same
  message and states they understand the consequences.

## Privacy and secrets

- Keep real personal paths, hostnames, and identities out of code, tests,
  fixtures, docs, and commit messages.
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

## Working style

- Read the relevant files before changing them. Make the smallest change that
  satisfies the task; do not add speculative abstractions or fallbacks.
- Fix root causes rather than suppressing symptoms.
