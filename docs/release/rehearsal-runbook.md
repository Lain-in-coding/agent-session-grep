# Release Rehearsal Runbook

> Current harness: all five entry points are directly compared (real loopback
> Web and a headless TUI snapshot); missing coverage is not a pass.
> Source-bound hosted verification is distinct from this clean-environment
> rehearsal. Each candidate still needs its own performance and clean-machine
> evidence; see the owner checklist for the dated canonical CI checkpoint.

This runbook defines the full release-rehearsal procedure for
agent-session-grep. It is executed per-platform (Windows, macOS, Linux) in a
clean environment before the owner makes the final go/no-go decision.

**Hard rule**: every step records its command, run id, wall-clock time, errors,
and a pass/fail verdict. Anything the docs don't cover, a command that doesn't
work, or an unexpected result is a defect and must be tracked and fixed.

---

## 0. Clean environment setup

### 0.1 Platform requirements

Each clean-environment rehearsal uses a clean VM or container image, not a
GitHub-hosted runner. A named successful hosted run is CI verification, not
clean-machine certification: hosted images have preinstalled toolchains.
Keep its source/run/attempt and status separate from this procedure's evidence.

| Platform | Image requirement | Notes |
|---|---|---|
| Windows | Windows 11 (clean install, no dev tools beyond the rehearsal toolchain) | PowerShell 7+ |
| macOS | macOS 14+ (clean VM or container, no Homebrew dev packages preinstalled) | zsh default shell |
| Linux | Ubuntu 22.04 LTS (clean container or VM) | bash default shell |

### 0.2 Toolchain

Install only what the rehearsal needs:

- Rust stable toolchain (`rustup` — the minimum supported toolchain for the
  workspace `rust-version`)
- Python 3.10+ (for the consistency script and evidence harnesses)
- Git (to clone the repo at the release tag)

### 0.3 Environment manifest

Before starting, fill in the environment manifest template at
`docs/release/environment-manifest.template.json`. Record:

- OS name, version, build number
- Clean image identifier (VM snapshot name or container image digest)
- Installer artifact SHA-256 hash
- Tool versions (rustc, cargo, python, git)
- Provider fixture license + redaction status

Manifests carry **aggregate environment facts only** — OS/build, clean-image
identifier, artifact hashes, toolchain versions, fixture license/redaction
status, run id. They must **never** contain personal paths, hostnames, or
operator identities. The manifest schema's `rehearsal.operator` field is an
opaque operator identifier, not a personal name. The local Windows/WSL
rehearsal evidence follows the same rule: manifests record the aggregate
environment, commit, and hashes only.

A completed manifest is the entry ticket — no manifest, no rehearsal.

### 0.4 Unsigned release artifact contract

`.github/workflows/release.yml` handles `v*` tag pushes and explicit
`workflow_dispatch` runs against an existing `v*` tag. It resolves one immutable
`source_commit` and passes it through reusable quality checks, builds, and
assembly. `release-verify.yml` exercises the same four targets without
publishing. A named successful verification run and downloaded Actions bundle
do not prove execution of the publication workflow, clean-machine support, or
an actual Release. Record evidence separately for each source and workflow.

The configured matrix matches the committed platform targets:

- `x86_64-pc-windows-msvc` (`.zip`, static CRT);
- `x86_64-unknown-linux-gnu` (`.tar.gz`);
- `x86_64-apple-darwin` (`.tar.gz`);
- `aarch64-apple-darwin` (`.tar.gz`).

Each archive is allowlist-built and contains only the canonical binary,
`README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `CHANGELOG.md`, `SECURITY.md`,
`NOTICE`, and the JSON/CSV third-party dependency inventory. The assembled bundle also
contains per-target `*.manifest.json` files, the common dependency inventory,
and `SHA256SUMS`. Manifests record target, version, full source commit,
Cargo.lock hash, archive/member hashes, and `unsigned: true`; they intentionally
contain no build-machine paths or identities.

During preparation, the workflow validates that the checked-out tag points
at `HEAD` and that `v<version>` matches `Cargo.toml`, Cargo metadata, and the
CLI entry in `Cargo.lock` before uploading common dependency inputs.
Before target-artifact upload, each built target must pass
`scripts/verify-release.py` using committed synthetic fixtures only.
A manual dispatch stores
the complete bundle as a GitHub Actions artifact but does **not** create a
GitHub Release. Separately authorized tag-push publication is create-new-only:
it refuses an existing draft or published Release, including one with zero
uploaded assets. A partial creation or publication error stops for owner review;
there is no automatic retry, cleanup/deletion, update, or asset replacement.
Corrections require a newly reviewed version, not a rerun that clobbers an old
release. The existing v0.1.0 source-only Release must remain unchanged.

`SHA256SUMS` and the self-reported manifests provide integrity and reproducible
provenance inputs; they are not signatures, notarization, or cryptographic
attestations. Those identity-backed controls remain external release gates.

---

## 1. Install

### 1.1 Build and install from source

```bash
cargo build --release --locked
# Run the platform install script:
#   Windows: pwsh scripts/install/install.ps1   (PowerShell 7+; scripts use $IsWindows)
#   macOS/Linux: bash scripts/install/install.sh
```

**Expected evidence**: install script exit code 0; binary present at the
user-level prefix; `agent-session-grep --version` prints the expected version.

**Run id**: record as `install-<platform>-<date>`.

---

## 2. Ingest / index synthetic corpus

### 2.1 Select the committed fixture and an isolated catalog

Run from the reviewed checkout root, using an already-built/installed binary
from that source. Use only the committed synthetic fixture
`scripts/evidence/fixtures/gate/claude/session-alpha.jsonl`; its known search
term is `retry`. Do not discover or read real user transcripts in this smoke.

`core_beta_benchmark.py --output-dir` writes reports, not a retained corpus:
its generated sources live in a temporary directory that is removed afterwards.
Use that benchmark for evidence in §8, not as a source-file exporter.

Bash (Linux/macOS):

```bash
ASG="$(command -v agent-session-grep)"
test -n "$ASG" && test -x "$ASG" || exit 1
REHEARSAL_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/asg-rehearsal.XXXXXX")" || exit 1
DB="$REHEARSAL_ROOT/asg.db"
FIXTURE="scripts/evidence/fixtures/gate/claude/session-alpha.jsonl"
```

PowerShell 7 (Windows):

```powershell
$ASG = (Get-Command agent-session-grep -CommandType Application -ErrorAction Stop).Source
$REHEARSAL_ROOT = Join-Path ([IO.Path]::GetTempPath()) ("asg-rehearsal-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $REHEARSAL_ROOT -ErrorAction Stop | Out-Null
$DB = Join-Path $REHEARSAL_ROOT 'asg.db'
$FIXTURE = Join-Path (Get-Location).Path 'scripts/evidence/fixtures/gate/claude/session-alpha.jsonl'
```

You may supply the absolute path of the just-built binary as `ASG` instead of
looking it up on PATH; verify its version and source first. Keep this new
catalog separate from any existing user data root. Retain the variables for
the remaining steps. Later command blocks use Bash syntax; in PowerShell use
`& $ASG` to invoke the same binary, `$DB` for the catalog, and check each native
exit code as below. Substitute actual IDs returned by search, never sample IDs.

### 2.2 First index and existing release smoke

Bash:

```bash
"$ASG" --db "$DB" --robot sync "$FIXTURE" || exit 1
"$ASG" --db "$DB" --robot search "retry" || exit 1
python scripts/verify-release.py --asg "$ASG" || exit 1
```

PowerShell:

```powershell
& $ASG --db $DB --robot sync $FIXTURE
if ($LASTEXITCODE -ne 0) { throw 'synthetic sync failed' }
& $ASG --db $DB --robot search 'retry'
if ($LASTEXITCODE -ne 0) { throw 'synthetic search failed' }
python scripts/verify-release.py --asg $ASG
if ($LASTEXITCODE -ne 0) { throw 'release smoke failed' }
```

**Expected evidence**: sync exits 0 with one Robot envelope, `data.committed > 0`
and `data.skipped == 0`; search returns real hits for `retry`. The existing
`verify-release.py` runs its bounded checks with the same committed fixture in
its own throwaway catalog. It does not build, install, publish, or exercise
Web; §9 covers the five real entry points separately. Preserve each verdict,
not only the last command's exit status. These smoke results alone are not
clean-machine or four-target certification.

**Run id**: `ingest-<platform>-<date>`.

---

## 3. Search

### 3.1 Lexical search

```bash
"$ASG" --db "$DB" --robot search "retry"
```

**Expected evidence**: hits returned; each hit has `id`, `score`, `session_id`,
`text`; `page.has_more` is a boolean; `outcome` is `success` or `partial`.

### 3.2 Semantic / hybrid search

```bash
# Build the bigram-hash embedding projection first (catalog-derived, rebuildable):
"$ASG" --db "$DB" --robot index embeddings

# Then the semantic/hybrid modes become effective (until then they fall back
# explicitly to lexical_fallback with a warning — never silently):
"$ASG" --db "$DB" --robot search "retry" --mode semantic
"$ASG" --db "$DB" --robot search "retry" --mode hybrid
```

**Expected evidence**: `index embeddings` reports `model_id: bigram-hash-v1`,
`dimension: 384`, `indexed > 0`. Semantic/hybrid searches report
`retrieval_mode: semantic` / `hybrid` with hits. Record per-mode latency and
result-set overlap. **Honesty note**: `bigram-hash-v1` is a fuzzy lexical
bigram vectorizer, explicitly **not** a semantic model; semantic/hybrid modes
are experimental and lexical remains the default.

**Run id**: `search-<platform>-<date>`.

---

## 4. Context

```bash
"$ASG" --db "$DB" --robot context "<session-id-from-search>"
```

**Expected evidence**: mainline messages returned in order; sidechains excluded
by default; evidence spans are present.

**Run id**: `context-<platform>-<date>`.

---

## 5. Resume dry-run

```bash
# Read-only resume metadata (fixed nullable fields; never echoes a source path):
"$ASG" --db "$DB" --robot get-session-resume "<session-id-from-search>"

# Dry-run execution preview (default, no provider process):
"$ASG" --db "$DB" --robot resume "<session-id-from-search>"
```

**Expected evidence**: `get-session-resume` reports `resume_available` as a
boolean and always includes nullable `provider_session_id` and
`original_working_directory` fields. `resume` defaults to a preview with
`executed: false`; command/cwd/permission fields can be null and the permission
mode is not verified. An unavailable or unsafe-to-render command is not
fabricated. First use can record the local preview marker but never launches
the provider, even with `--yes`. A subsequent explicit `--yes` request is the
opt-in for real execution; do not execute native resume in this synthetic
rehearsal.

**Run id**: `resume-<platform>-<date>`.

---

## 6. Handoff pack generation

```bash
"$ASG" --db "$DB" --robot handoff "retry"
```

**Expected evidence**: pack conforms to `HandoffPack` schema version `1.0`
(`schema_version: "1.0"`); evidence and inference are in separate sections
(deterministic packs carry `inference: []`); budget/truncation/redaction rules
are applied; the pack is deterministic (two runs produce the identical
`pack_id` and output).

**Run id**: `handoff-<platform>-<date>`.

---

## 7. Web UI walkthrough

```bash
"$ASG" --db "$DB" serve
```

The server prints the effective loopback URL with a per-session bearer token
to stderr:

```text
asg serve: open http://127.0.0.1:<port>/#token=<32-hex>
```

Walk through with the token (`Authorization: Bearer <token>`, loopback Host
required): `/` (embedded Web UI), `/api/status`, `/api/search?q=`,
`/api/context?session=`, and the canonical projection endpoint
`/api/projection/search?q=` used by the five-entry consistency harness.
Verify parity with CLI output for the same queries; verify no-token requests
return 401 and non-loopback Host requests return 403.

---

## 8. Evidence review

```bash
python scripts/evidence/core_beta_benchmark.py run --profile smoke \
    --output-dir "$REHEARSAL_ROOT/benchmark-reports" --binary "$ASG"
```

**Expected evidence**: benchmark report JSON with all invariant verdicts
passing, then `validate-report` confirms the report is well-formed.

**Run id**: `evidence-<platform>-<date>`.

---

## 9. Five-entry-point consistency

```bash
python scripts/rehearsal/compare_entrypoints.py \
    --binary "$ASG" \
    --out "$REHEARSAL_ROOT/consistency-report.json"
```

**Expected evidence**: `overall_verdict == "consistent"`; every declared entry
point (cli, mcp, robot, web, tui) is **directly compared** for the canonical
search operation — the harness launches the real loopback `serve` process for
Web and drives the TUI's headless `--snapshot-json` projection. `skipped`,
`aliases`, and `unimplemented` are all empty; an unimplemented entry point
fails the harness (exit 1), never a skip-as-pass.

**Run id**: `consistency-<platform>-<date>`.

---

## 10. Privacy final check

### 10.1 Zero telemetry

Offline mode is implemented: the global `--offline` flag is registered in every
prefix scanner and fails closed for future network capabilities
(`capability_not_supported`); `doctor`/`hook` report the flag. The default
build carries no HTTP client dependency, and the only socket is `serve`'s
loopback `TcpListener` — enforced by `tests/network_egress.rs` and the
`security-audit` workflow step.

1. Run the full rehearsal with network capture active (Wireshark / tcpdump /
   `netstat`). Verify zero outbound connections except explicit model downloads.
2. Run `agent-session-grep --offline` through all core commands. All must
   succeed without network.

### 10.2 Redaction spot-check

Verify cross-boundary outputs (Web, Handoff, MCP, Robot) apply default
redaction. Inject a secret-pattern fixture and confirm it never appears in
output.

1. Create a synthetic transcript fixture containing known secret patterns
   (GitHub PAT, AWS secret key, API key) and sync it into the rehearsal
   catalog.
2. Search across all four cross-boundary entry points (`--output json` Robot,
   MCP `search_sessions`, Web `/api/search`, handoff pack) for the injected
   secret terms.
3. Assert that every occurrence of the secret pattern in output is replaced
   by its `[redacted:...]` placeholder. Confirm the CLI plain-text output
   (local, no redaction) still shows the raw value for comparison.

### 10.3 Log / diagnostic audit

Inspect stderr and any log files produced during the rehearsal. Confirm no
transcript content, absolute source paths, provider-native ids, fingerprints,
usernames, or hostnames appear in diagnostics.

---

## 11. Performance final check

```bash
# Rebuild the release binary first; write generated evidence only under the
# ignored output directory.
cargo build --release --locked -p agent-session-grep-cli
python scripts/evidence/open_source_gate_benchmark.py run \
  --binary target/release/agent-session-grep \
  --profile rehearsal \
  --output-dir scripts/evidence/out
python scripts/evidence/open_source_gate_benchmark.py validate-report \
  scripts/evidence/out/gate-manifest-rehearsal.json
```

Run the full Gate D benchmark suite against the rehearsal corpus. Verify all
six invariants pass. Refresh the benchmark report with this run's numbers,
recording the measured commit in the external rehearsal evidence; do not
commit the generated manifest from `scripts/evidence/out/`.

---

## 12. Release materials check

Verify that README, quickstart, comparison table, demo dataset, and benchmark
numbers are mutually consistent. Check LICENSE, third-party attributions, and
fixture provenance.

For a release rehearsal, also inspect the assembled unsigned bundle: all four
promised target archives and manifests are present, every archive is listed in
`SHA256SUMS`, each manifest's tag/version/commit/Cargo.lock hash matches the
checkout, and no archive contains `target/`, a database, or a transcript. Do
not record a checksum or manifest as signing, notarization, or attestation
evidence.

---

## 13. Uninstall

```bash
# Windows: pwsh scripts/install/uninstall.ps1
# macOS/Linux: bash scripts/install/uninstall.sh
```

**Expected evidence**: exit code 0; binary removed; idempotent (second run
reports "not installed", exit 0); no directory recursively deleted.

**Run id**: `uninstall-<platform>-<date>`.

---

## 14. Reinstall idempotency

Repeat §1. Verify the second install succeeds identically. The rehearsal db is
untouched (install must not delete user data).

**Run id**: `reinstall-<platform>-<date>`.

---

## 15. Go/No-Go report

Fill in `docs/release/go-no-go.template.md` (or a generated non-template draft
derived from it) with:

- All run ids and their pass/fail verdicts
- Residual risk list
- Five-entry consistency report
- Privacy / performance / materials check results
- Owner sign-off block

`docs/release/go-no-go.2026-08-16.md` is the historical No-Go draft for that
date, not the current candidate's report; preserve it unchanged. Fill a fresh
report for the actual candidate version and full source SHA, then submit it
to the owner for a separately authorized public-release decision. On Windows the local rehearsal evidence (including any WSL Linux
rehearsal) is recorded in aggregate — environment, commit, and hashes only,
with no personal paths.

---

## Evidence artifact checklist

| Step | Artifact | Format |
|---|---|---|
| 0 | environment manifest | JSON |
| 0a | unsigned target archives, manifests, dependency inventory, and checksums | ZIP/TAR.GZ + JSON/CSV/TXT |
| 1 | install log | text |
| 2 | ingest robot envelope | JSON |
| 3 | search robot envelope | JSON |
| 4 | context robot envelope | JSON |
| 5 | resume robot envelope | JSON |
| 6 | handoff pack | JSON |
| 7 | Web UI screenshots + parity notes | PNG + markdown |
| 8 | benchmark report | JSON |
| 9 | consistency report | JSON |
| 10 | privacy audit notes | markdown |
| 11 | Gate D benchmark report | JSON |
| 12 | materials checklist | markdown |
| 13 | uninstall log | text |
| 14 | reinstall log | text |
| 15 | go/no-go report | markdown |

All artifacts are stored under `evidence-output/rehearsal-<date>/` (gitignored).
