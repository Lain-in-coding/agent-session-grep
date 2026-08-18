# Contributing to agent-session-grep

Thanks for your interest in contributing. This document defines the commit and
collaboration standards for this repository. They are strict on purpose: the
project is local-first and privacy-sensitive, so keeping secrets and personal
data out of history is the highest priority.

## Contribution entry points

- Provider adapters: [Provider Adapter Contributor Guide](docs/PROVIDER-ADAPTER-CONTRIBUTOR-GUIDE.md)
- Bugs: [bug report form](.github/ISSUE_TEMPLATE/bug-report.yml)
- Ideas: [feature request form](.github/ISSUE_TEMPLATE/feature-request.yml)
- Pull requests: [pull request template](.github/pull_request_template.md)

The adapter guide adds provider-specific evidence and privacy requirements; the
commit, collaboration, and quality standards below remain in force.

## Commit messages (Conventional Commits)

1. Format: `type(scope): subject`, where `type` is one of
   `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`.
2. Subject line ≤ 50 characters, imperative mood ("add", not "added"), no
   trailing period.
3. The body explains **why** the change was made, not what changed (the diff
   already shows what). Wrap the body at 72 characters.
4. One logical change per commit (atomic commits). Do not bundle unrelated
   changes.
5. Never `git add .` blindly. Stage specific files so unrelated changes do not
   slip in.

## Preventing secret and data leaks (highest priority)

6. Build artifacts, dependencies, and caches never enter the repository
   (`target/`, `*.db` and its sidecar files).
7. `.gitignore` excludes `.env`, `*.pem`, `*.key`, `credentials*`, `.mcp.json`.
8. Secrets go through environment variables. Only commit an `.env.example`
   template, never real values.
9. Keep real personal paths, hostnames, and identities out of code, tests,
   fixtures, docs, commit messages, and pull request text.
10. Run a repository-wide redaction scan before publishing or pushing.

## Collaboration workflow

11. Work on a feature branch and open a pull request into `main`. Do not push
    directly to `main`.
12. Do not merge your own pull request. Merging is always the repository
    owner's decision, even when checks pass.
13. Do not amend, squash, or rebase commits that have already been pushed,
    unless explicitly requested.
14. Run the local quality gate before committing:
    `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
    and `cargo test --workspace`.
15. Commits are authored by the repository owner only. Do not add AI
    co-authors, "Generated with ..." footers, or command transcripts to commit
    messages.

## Destructive operation policy

Destructive Git and filesystem commands — `git reset --hard`, `git clean -fd`,
`git push -f`, `rm -rf`, and similar — are prohibited unless the requester
gives the exact command in the same message and states they understand the
consequences.
