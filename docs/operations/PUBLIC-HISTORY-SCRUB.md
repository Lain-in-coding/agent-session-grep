# Public History Scrub Runbook

## Status and boundary

A current-tree path scan is not a history or credential audit. Publication
requires evidence for the exact candidate, its introduced history and metadata,
and separate owner approval. The existing canonical repository is the future
product authority; do not create a competing repository, import development
ancestry, rewrite history, or replace published assets as part of a tree import.

The older history-rewrite procedures below remain reference material for a
separately authorized incident response, not instructions to perform a rewrite.

## Deterministic public export (v2)

Run the reviewed exporter from the canonical tool checkout, with a fixed source
commit and an empty destination **outside the source checkout and its Git
metadata**. Do not execute an exporter/scanner from an arbitrary source tree.
The destination and its ancestors must not be symlinks or Windows reparse
points. Use a privately owned destination with no concurrent writers.

```powershell
$destination = Join-Path $env:TEMP "agent-session-grep-public-tree"
python scripts/release/export_public_tree.py --repo <source-checkout> `
  --commit <full-reviewed-source-sha> --destination $destination
python -m unittest discover -s scripts/release -p "test_export_public_tree.py" -v
```

The tool resolves the commit once, ignores replacement refs, enumerates Git
objects with NUL-delimited names, and reads blobs by object ID, not checkout
files. It validates the complete source path inventory and all exported bytes
before creating output. Symlinks, gitlinks, traversal, ambiguous Windows names,
case/file-directory collisions, non-normalized Unicode and destination links
are rejected. Tab/newline names are parsed as single names and then rejected,
not split into accidental paths. Nonempty destinations are never overwritten.
A validation failure creates no output; an I/O failure or privacy finding can
leave a candidate for inspection. Do not publish it or silently retry into it.

Private coordination roots and generated `scripts/evidence/out/` are excluded.
`spikes/` is deliberately included because the public ADRs/RFCs cite its
measurements. `AGENTS.md`, when present in the source, is replaced by the
reviewed `scripts/release/public_AGENTS.md` projection. That template preserves
the canonical standalone architecture, privacy and contribution guidance and
must preserve root `AGENTS.md` content in canonical LF form. A targeted
`.gitattributes` rule pins only this template to LF so checkout newline
conversion cannot change its bytes/profile hash. It does not require excluded
development tooling. This projection, its output mode and SHA-256 are declared
in the profile, not hidden as a post-export edit.

Only the scanner beside the reviewed exporter executes, always using its
`public` profile; `--repo` never supplies executable scanner/profile code. The
export manifest records the exact exporter/scanner/template byte hashes and
profile version/hash. The profile hash binds the rules and exclusions as well
as the projection. Tool hashes identify the actual executed artifacts, even
when the tool checkout is not committed; a nearby Git HEAD alone would not.
No timestamp, machine path, source remote, or mutable ref enters the manifest.
This is reproducibility/provenance evidence, not a signature or trust grant.

### Immutable import snapshots

The generated v2 manifest lives at:

```text
docs/operations/imports/public-tree-v2-<full-source-sha>.json
```

It records the source commit/tree IDs and sorted path, Git mode (`100644` or
`100755`), byte length and SHA-256 records. It excludes itself from its file
inventory, so there is no self-hashing cycle. Repeating the same source and
reviewed tool/profile bytes produces the same snapshot bytes. A collision with
an existing snapshot path is an error, not an overwrite.

A source root `PUBLIC-TREE-MANIFEST.json` is accepted only as a valid v1
manifest. Its original bytes are archived, unchanged, under:

```text
docs/operations/imports/public-tree-v1-<original-bytes-sha256>.json
```

The v2 inventory hashes that archived file and declares it as `prior_manifest`.
Do not infer absent v1 modes from hashes; reconcile against the initial formal
Git tree and record any independently verified mode correction. Unknown or
malformed root manifests and archive collisions stop the export.

During canonical integration, preserve the existing v1 bytes and new v2
snapshot in this imports directory and record the actual import commit and
reviewed target-only changes separately. Do not carry a root manifest forward
as a purported checksum of the evolving canonical tree. Snapshots describe
**the exported input**, not later reconciled edits or every future commit.
They remain immutable; future development follows the public contribution
contract, not continuous re-export or manifest regeneration.

Only the exact, freshly generated profile/exclusion metadata is omitted from
its byte-checked manifest during the exporter's scan (it necessarily declares
excluded roots). Profile drift is rejected; all other manifest fields are
scanned, including extra fields supplied by a caller. Historical manifests and
all source content are scanned with the unchanged public rules. A source that
already contains v2 snapshots and no root v1 manifest keeps those snapshot bytes
unchanged as ordinary inventory entries; their policy metadata can also fail
the scan. Re-exporting does not grant historical metadata a new exemption.
In particular, an old v1 `excluded_prefixes` field can contain an internal
marker and fail the scan after archival. Preserve that evidence and request a
separately reviewed resolution; do not rewrite the provenance, broaden the
allowlist, or report a failed scan as success. Export success is not a
credential/history audit or permission to publish.

### Explicit Git index modes, including Windows

Filesystem `chmod` alone does not preserve executable bits in a Windows Git
index. Export **never** initializes a repository, stages source/destination
content, changes refs, or implicitly repairs an index. After reviewing a
successful candidate, the owner may explicitly initialize and stage **only the
disposable export** (not the development or existing canonical checkout):

```powershell
git -C $destination init
$snapshot = "docs/operations/imports/public-tree-v2-<full-source-sha>.json"
$manifest = Get-Content -LiteralPath (Join-Path $destination $snapshot) -Raw |
  ConvertFrom-Json
$paths = @($manifest.files.path) + @($snapshot)
$paths # Stop here and review this exact inventory before staging.
# After review, stage one literal path per command (no wildcard expansion or
# command-line length limit). Filters/attributes that change bytes are detected.
foreach ($path in $paths) {
  git -C $destination --literal-pathspecs -c core.autocrlf=false add -- $path
  if ($LASTEXITCODE -ne 0) { throw "Explicit-path staging failed; stop and inspect." }
}
python scripts/release/export_public_tree.py --destination $destination `
  --manifest $snapshot --index-modes check
# A mode mismatch is expected if Windows staged executable files as 100644.
# Only after reviewing that mismatch:
python scripts/release/export_public_tree.py --destination $destination `
  --manifest $snapshot --index-modes apply
python scripts/release/export_public_tree.py --destination $destination `
  --manifest $snapshot --index-modes check
git -C $destination ls-files --stage
```

The explicit operation requires an independent destination Git directory and
exact snapshot file inventory. Every working and staged blob must match its
recorded bytes/hash before **any** mode update. It rejects missing, extra,
unmerged, symlink/reparse or drifted content; no filters/hooks run during mode
application. The operation exclusively acquires Git's real index lock before
reading any staged entries. Only necessary mode fields change in a private
candidate via a NUL-delimited native Git update. It revalidates that candidate
and working inventory before atomically replacing the real index. Concurrent
Git writers are refused; validation/update failures leave the real index
unchanged, and an existing writer's lock is never removed. It does not stage
content or copy old source refs. `--manifest` is a literal destination-relative v2 path. Git directory,
work-tree, index and object-directory environment overrides are rejected.

These snapshot checks apply to an unmodified export, not to a merged canonical
working tree with retained target-only edits. For canonical reconciliation,
review modes alongside bytes and verify the actual staged tree separately.
The known initial import defects are `scripts/install/gate_smoke.sh`,
`install.sh`, `smoke.sh`, and `uninstall.sh`: all four require `100755` in Git.
Apply those corrections only through explicit owner/coordinator staging;
preserve the canonical bytes, especially the independently changed `smoke.sh`.
Record mode-only corrections separately from source content reconciliation.

For an initialized repository, run the public scanner and its tests explicitly:

```text
python scripts/evidence/privacy_scan.py --repo . --profile public
python -m unittest discover -s scripts/evidence -p "test_privacy_scan.py" -v
```

A raw export is scanned by the exporter's directory scanner; standalone
`privacy_scan.py` requires Git-tracked files. Record findings, skipped checks
and tool errors distinctly. Do not substitute a local Windows run for hosted
Linux/macOS tests or claim a credential scanner ran when it did not.

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

## Executable export contract

### Scope and trigger

This contract applies when exporting a fixed source commit or checking/applying
Git modes in an independently staged export. It does not authorize publishing,
history rewriting or applying a raw-source snapshot to a reconciled working tree.

### Signatures

```text
export_public_tree.py --repo <source> --commit <ref> --destination <empty-dir>
export_public_tree.py --destination <export> --manifest <relative-v2-path> --index-modes check
export_public_tree.py --destination <export> --manifest <relative-v2-path> --index-modes apply
```

### Inputs, outputs and environment

The source ref resolves once to a commit object. The output is the declared
public projection plus an immutable v2 snapshot; v1 bytes remain historical
evidence. Index operations accept that exact snapshot and staged inventory,
not arbitrary partial path lists. Tool/scanner/profile bytes determine provenance;
ambient Git directory/index/object overrides are rejected, not silently trusted.

### Validation and error matrix

| Case | Result | Mutation boundary |
| --- | --- | --- |
| Valid export or matching index check | Exit 0 | Export writes only its isolated destination; check preserves index content |
| Public-rule finding | Exit 1 | Export is not approved for publication; evidence is retained |
| Invalid source, path, manifest, destination, index or Git operation | Exit 2 | Export prevalidation writes nothing; rejected index transaction preserves the real index |
| Mode mismatch in check mode | Exit 2 | Explicit review/apply is required; no automatic mode repair |
| Existing index lock or incompatible environment | Exit 2 | Another writer's lock/state is not removed or overridden |

### Good, base and bad cases

- Good: two fresh destinations from identical source/tool/profile bytes have
  identical snapshot bytes and verified payload hashes/modes.
- Base: Windows stages a Unix script as100644. Check rejects; explicit apply
  changes only its recorded mode to100755 with the blob unchanged.
- Bad: a source subdirectory hides an output inside the actual source root;
  a path collides on Windows; a malformed manifest uses a non-string path or
  boolean count; an unmerged/extra/drifted index entry appears. Reject rather
  than guessing, following a link or updating a partial inventory.

### Required tests and assertion points

The exporter suite must assert deterministic objects/projection under both
checkout newline policies, NUL-safe portable paths, untouched sources on
rejection, v1 byte preservation, non-exempt historical snapshots, and scanning
of non-profile metadata. Transaction tests compare real index bytes and blob
IDs on success/failure and preserve other writers' lock ownership. CLI tests
assert exit codes, absent traceback/path disclosure and no destination creation
for invalid inputs. Use synthetic fixtures, never real session data.

### Wrong versus correct

| Wrong | Correct |
| --- | --- |
| Treat matching file bytes as complete export integrity | Verify hashes, modes, profile and actual destination Git tree |
| Hash platform-dependent template checkouts | Pin the public template to LF and test different checkout policies |
| Validate, then update using stale staged OIDs | Lock first, validate a private candidate, recheck, then atomically publish |
| Blanket-stage a directory or waive the whole manifest scan | Stage reviewed literal inventory paths; exempt only exact tool-owned metadata |
| Treat a failed historical-content scan as successful migration | Keep the failure/evidence and resolve it through the reviewed integration |
