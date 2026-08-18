# Public History Scrub Runbook

## Status and boundary

The public-tree privacy path cleanup has scrubbed the production tree:
provider module docs, product docs, and this script/runbook set carry no
personal usernames, local checkout roots, or agent worktree coordinates.

The scanner also reports paths that remain in internal coordination records,
which are working notes rather than published files. The exporter drops those
records, and the owner must rerun the scanner below on the exact publication
SHA before publishing. The repository gate is:

```text
python scripts/evidence/privacy_scan.py --repo .
python -m unittest discover -s scripts/evidence -p "test_privacy_scan.py" -v
```

The owner may create a clean public-tree candidate without rewriting the
development history by exporting the exact publication SHA. This is the
preferred Option A mechanical rehearsal:

```powershell
$destination = Join-Path $env:TEMP "agent-session-grep-public-tree"
python scripts/release/export_public_tree.py --repo . `
  --commit <publication-sha> --destination $destination
python -m unittest discover -s "$destination/scripts/release" -p "test_*.py"
```

The exporter copies only tracked files, excludes internal coordination
directories and generated `scripts/evidence/out/` output, writes
`PUBLIC-TREE-MANIFEST.json` with the source SHA and per-file SHA-256, and runs
the same privacy rules against the ordinary exported directory. It does not
modify refs or repository visibility; review the destination and publish it
only after the owner chooses Option A.

This does **not** clean older commits. Git history can still retain superseded
copies of personal paths. Do not publish until the owner chooses one of these
publication strategies:

1. Publish a new repository from the cleaned current tree, intentionally
   excluding the development history; or
2. Rewrite the development history with `git-filter-repo`, validate the
   result, coordinate every existing clone, and then publish the rewritten
   repository.

This document is a decision and verification runbook. It does not authorize or
perform a destructive history rewrite.

## Preconditions

- Rotate any exposed credential before rewriting. Paths alone do not require
  credential rotation, but use the same incident procedure if a secret is found.
- Freeze pushes and ask collaborators to stop work during the rewrite window.
- Install a current `git-filter-repo` release and use Git 2.36 or newer.
- Work only in a disposable fresh clone. When cloning from a local filesystem,
  use `--no-local` so the clone does not share objects with the source.
- Archive the source repository separately before any rewrite.

Never run the commands below in a working checkout that contains unique local
work. Do not normalize this procedure by adding `--force`; the fresh-clone
safety check is intentional.

## Analyze without modifying history

Set the source remote URL in the current shell, then create a disposable mirror
clone outside the source checkout:

```powershell
$sourceUrl = "<source-repository-url>"
git clone --mirror $sourceUrl public-history-audit.git
git -C public-history-audit.git filter-repo --analyze
```

`--analyze` does not modify the repository. Review
`public-history-audit.git/filter-repo/analysis/` for suspect paths and sizes.
Also search every historical blob for the exact strings identified during the
current-tree audit. Examples:

```powershell
git -C public-history-audit.git log -S"<username>" --all -p --
git -C public-history-audit.git log -S"<old-local-root>" --all -p --
git -C public-history-audit.git log --all --name-only --pretty=format: |
  Select-String -Pattern "Users/|/home/|/Users/|<old-checkout-root-name>|worktrees"
```

Do not put real personal or credential values in this tracked runbook or in a
committed replacement file.

## Measured read-only history audit

Snapshot measured 2026-08-18 with strictly read-only commands:
`git log --all -G<pattern>` over every ref, plus per-commit diff
attribution (`git show <commit> --format= --unified=0`) to count introduced
match-lines per file. Counts only; no personal value is recorded here.

| pattern family | matching commits | introduced match-lines | distinct files | files still in HEAD | files inside the export set |
| --- | ---: | ---: | ---: | ---: | ---: |
| Windows user home paths | 17 | 28 | 16 | 16 | 9 |
| Unix user home paths (`/Users/`, `/home/`) | 17 | 27 | 14 | 14 | 13 |
| machine roots (checkout/reference roots) | 24 | 73 | 40 | 40 | 11 |
| worktree coordinates | 9 | 31 | 15 | 15 | 0 |
| secret shapes (GitHub PAT, AWS key, private key block) | 6 | 18 | 3 | 3 | 2 |
| union of all families | 45 distinct commits | 177 | 61 | 61 | 29 |

File-family distribution of the union (match-lines / files): internal
coordination records excluded by the exporter 104 / 32; product crates 65 / 23;
docs and release notes 4 / 3; spikes 3 / 2; root-level schemas 1 / 1.

Reading the numbers:

- Every match-carrying file still exists at HEAD, and the current-tree scanner
  reports 0 findings. The 29 union files inside the export set carry only
  synthetic fixtures already allowlisted by the scanner (test vectors and
  redaction examples); the remaining 32 are internal coordination records that
  the exporter drops.
- The 6 secret-shape commits contain only redaction rule definitions and
  synthetic test vectors (AWS/GitHub documentation examples), not real
  credentials. This measurement triggers no credential rotation; rerun the
  exact-string searches in the previous section if a later audit finds a new
  shape.
- Worktree coordinates appear only in excluded internal records: 0 files inside
  the export set.

Export verification at this snapshot: the exporter copied 277 tracked files from
the measured commit; its built-in scanner and a standalone scanner run over the
destination both reported 0 findings; the scanner and exporter unittest gates
were green. History was not modified by this audit.

## Preview text replacement

Create an untracked replacement file outside the repository. Each line is a
literal replacement expression unless it starts with `regex:` or `glob:`.
Keep replacements explicit and reviewable, for example:

```text
<exact-old-user-home>==><user-home>
<exact-old-checkout-root>==><repo>
<exact-old-reference-root>==><user-home>/reference-src
```

Preview the rewrite in the disposable clone:

```powershell
git -C public-history-audit.git filter-repo --dry-run --replace-text "<absolute-path-to-replacements.txt>"
```

`--dry-run` does not change refs. It writes original and filtered fast-export
streams under `filter-repo/` for comparison. Inspect those streams and rerun the
history searches above before approving a real rewrite.

## Owner decision: rewrite or publish a clean repository

### Decision checklist

Complete this checklist at the publication SHA before either option is
executed. The rewrite itself is never executed from this runbook.

- [ ] Review the measured audit snapshot above and the current-tree scan
      result at the publication SHA.
- [ ] Choose and record the strategy: Option A (publish the exported clean
      tree as a new repository, dropping the development history) or
      Option B (`git-filter-repo` rewrite of the development history).
- [ ] Credential rotation check: the measured secret-shape hits are all
      redaction rules and synthetic test vectors. If any exact-string search
      finds a real credential instead, rotate it before proceeding and treat
      the exposure as an incident.
- [ ] Collaborator freeze (Option B only): ask every collaborator to stop
      pushing for the rewrite window and plan to delete or re-verify every
      clone afterwards. Option A needs no freeze, only that pushes stop at
      the chosen publication SHA.
- [ ] Backup: archive the source repository before any rewrite or
      publication decision.
- [ ] Record the chosen option, the publication SHA, and the date in the
      release record.

### Option A: new public repository

Create a new repository from an exported clean tree or a new root commit. This is
the lowest-risk choice when preserving development commit identity is not a
public requirement. Run the current-tree scanner in the exported tree,
review `git ls-files`, then publish only after all release gates pass.

### Option B: rewrite the development history

Only after owner approval, repeat the operation in a second disposable fresh
mirror clone and enable sensitive-data cleanup:

```powershell
git clone --mirror $sourceUrl public-history-rewrite.git
git -C public-history-rewrite.git filter-repo --sensitive-data-removal --replace-text "<absolute-path-to-replacements.txt>"
```

A rewrite changes commit IDs. `git-filter-repo` normally removes `origin` to
prevent accidental mixing of incompatible old and new histories. Review the
result before restoring any remote. The final force-push or public-repository
creation is an owner action and is intentionally not included as an executable
step here.

## Validate the rewritten candidate

In a non-bare checkout made from the rewritten candidate, run:

```powershell
python scripts/evidence/privacy_scan.py --repo .
python -m unittest discover -s scripts/evidence -p "test_privacy_scan.py" -v
git diff --check
```

Search all refs for every replaced value and historical path family:

```powershell
git log -S"<username>" --all -p --
git log -S"<old-local-root>" --all -p --
git log --all --name-only --pretty=format: |
  Select-String -Pattern "Users/|/home/|/Users/|<old-checkout-root-name>|worktrees"
```

For each first changed commit reported by `--sensitive-data-removal`, verify that
no ref retains it:

```powershell
git cat-file -t <first-changed-commit>
git for-each-ref --contains <first-changed-commit>
```

The `cat-file` check must fail with a missing-object error after cleanup. Any
reported retaining ref blocks publication. Repeat the scan against a fresh clone
from the exact candidate remote; local object pruning alone does not prove the
server no longer retains old refs.

## Publication checklist

- Owner selected and recorded Option A or Option B.
- Current-tree privacy scan and unittest are green on the exact publication SHA.
- Historical exact-string and path-family searches return only reviewed
  synthetic fixtures or documentation commands.
- No real provider transcript, database, credential, local build artifact, or
  ignored reference checkout is tracked.
- Existing clones are deleted and recloned, or explicitly cleaned and verified,
  so an old branch cannot reintroduce rewritten history.
- Repository visibility changes only after the final owner review.

## References

- `git-filter-repo` project and fresh-clone safety:
  <https://github.com/newren/git-filter-repo>
- Official manual (`--analyze`, `--dry-run`, `--replace-text`, and
  `--sensitive-data-removal`):
  <https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt>
