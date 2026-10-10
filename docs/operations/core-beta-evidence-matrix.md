# Core Alpha / Cross-platform Beta Evidence Matrix

> Historical imported evidence: run identifiers and results below describe
> earlier development, not verified runs of the canonical reconciliation.
> Their original repository attribution is unresolved in this public record;
> do not construct canonical Actions links from those IDs or use these rows to
> certify this candidate. Fresh SHA-bound canonical runs are required.
> Later development-side installer/provider-run claims were not promoted here
> because they belong to a different repository, not this candidate.


> Evidence accounting record
>
> - status: **Draft**
> - scope: evidence for implemented 0.1 Core Alpha and 0.2 Cross-platform Beta work
> - workflow: `.github/workflows/core-beta-evidence.yml`
> - interpretation: local smoke numbers and configured CI jobs are evidence anchors, not formal SLOs or release certification

## Status vocabulary

- `locally_verified`: executed evidence is present in this repository and names the environment used.
- `ci_configured_only`: an exact CI job exists, but no successful run URL or downloaded artifact is recorded here.
- `ci_verified`: a named CI run of that exact job completed successfully on a GitHub-hosted runner, and the run is identified below. This is weaker than `locally_verified` in reviewability (artifacts expire after 7 days) and is not minimum-OS, clean-machine, or release certification.
- `externally_blocked`: the required host, identity, credential, or release infrastructure is unavailable.
- `not_implemented`: feasibility evidence exists, but the corresponding production API or production-level evidence helper does not.

## Recorded CI run

- repository attribution: historical imported record; not a canonical run
- workflow: `core-beta-evidence`, run `30165919066`, triggered by pull request #1
- source commit: as recorded by that workflow run
- outcome: all four runner/target jobs reported `success`
- retention: uploaded artifacts expire 7 days after the run; after expiry the run conclusion remains but the artifacts are no longer downloadable

A `ci_verified` row means the named run above passed that job. It does not mean an artifact from that run has been downloaded and reviewed.

## Evidence matrix

| Evidence ID | Claim or target | Status | Reproducible evidence | Exact caveat |
|---|---|---|---|---|
| `CB-WIN-X64-BUILD-001` | Windows x64 release build on `x86_64-pc-windows-msvc` | `locally_verified` | `spikes/cross-platform-packaging/EVIDENCE.md` | The recorded run is a local Windows build. It is not clean-machine installation evidence, a signed artifact, or release certification. |
| `CB-BENCHMARK-WIN-X64-001` | Full-profile startup, sync, search/show/get, storage-size, artifact-size, and peak-RSS evidence | `locally_verified` | `docs/evidence/core-beta/88d86f4/core-beta-benchmark-full.json`; `scripts/evidence/core_beta_benchmark.py` | The report is a local Windows evidence anchor, not an SLO. Recovery duration remains `not_implemented`. The harness built the measured binary from the pinned workspace using `cargo build --locked --release` and records its SHA-256 and provenance. |
| `CB-WRITER-LEASE-SPIKE-001` | Cross-process lock contention and forced-holder termination allow reacquisition | `locally_verified` | `spikes/data-root-locking/EVIDENCE.md` | This is feasibility-spike evidence. Production `WriterLease` also has same-process unit coverage; production process evidence is tracked separately. |
| `CB-WAL-SNAPSHOT-SPIKE-001` | WAL-aware backup and `VACUUM INTO` produce consistent snapshots; copying only the main database is unsafe | `locally_verified` | `spikes/sqlite-snapshot-wal/EVIDENCE.md` | This is feasibility-spike evidence. A production snapshot or bundle API is not implemented. |
| `CB-SOURCE-SNAPSHOT-SPIKE-001` | Content fingerprint detects equal-length source replacement | `locally_verified` | `spikes/source-snapshot/EVIDENCE.md` | The existing evidence is a Windows feasibility spike; it is not a cross-platform production certification. |
| `CB-CI-WIN-X64-001` | Windows Server 2022 x64 build, direct CLI smoke, SQLite adapter tests, and storage spikes | `ci_verified` | Run `30165919066` job `Windows x64 / MSVC`; `.github/workflows/core-beta-evidence.yml` | The job passed on `windows-2022`. It enables static CRT for its release build, but no clean-machine runtime or Windows 10 minimum-OS test is configured, and no artifact from the run has been downloaded and reviewed. |
| `IB-CI-INSTALLER-001` | Installer + uninstaller + CLI/MCP surface smoke script on all three hosted OS targets | `ci_configured_only` | `.github/workflows/ci.yml` job `installer` | The job is configured but has not yet produced a named successful run, so it is not yet `ci_verified`. Hosted runners are not clean machines (toolchain preinstalled): passing establishes installer-script smoke, not clean-machine installation. |
| `IB-CI-PROVIDER-EVIDENCE-001` | Claude and Codex provider evidence tests (golden byte pins, canonical output, fixed-seed properties, source-span round trips) plus the open-source gate benchmark, executed per named runner/target | `ci_configured_only` | `.github/workflows/core-beta-evidence.yml` steps `Claude and Codex provider evidence tests` and `Open-source gate benchmark` (added 2026-08-16) | The steps are configured but no run of this exact configuration is named in `## Recorded CI run`, so this stays `ci_configured_only`. Recorded run `30165919066` predates them and exercised only the SQLite adapter tests and storage spikes. RFC-0002 §6 cross-target provider evidence is not satisfied until a named successful run covers these steps on all four runner/target pairs. Locally verified on Windows x64 and WSL2 Ubuntu 22.04 (gate manifest `pass: true`, all four threshold metrics measured), which is single-machine evidence, not cross-target certification. |
| `IB-REAL-DATA-REGRESSION-001` | Repeatable, auditable authorized real-data regression process | `locally_verified` (green full-corpus run) | `scripts/evidence/real_data_regression.py` + `scripts/evidence/test_real_data_regression.py`; self-test on synthetic fixtures passes (12 tests) and runs in the `installer` job; recorded authorized local run: `docs/evidence/integration-beta/real-data-regression.md` | The green full-corpus run, generated `2026-08-09T21:10:16Z`, passed all six invariants with harness exit 0 over 1,242 source files (1,177,479,794 bytes): 164,136 emitted, 0 skipped; 150,091 de-duplicated messages, 231 sessions, 1,240 documents; context 231 sessions with 0 failures; 659/659 byte-precision spans; rebuild stable (catalog 151,562 -> 151,562). Two later full-corpus runs also passed all six invariants: `2026-08-12T23:51:23Z` (1,328 sources, 1,253,494,481 bytes; 180,218 emitted, 0 skipped; 242 sessions; 630/630 byte-precision spans; rebuild stable, catalog 166,380 -> 166,380) and `2026-08-13T00:26:57Z` (1,330 sources, 1,255,049,984 bytes; 180,718 emitted, 0 skipped; 242 sessions; 630/630 byte-precision spans; rebuild stable, catalog 166,882 -> 166,882). The 08-13 run used the renamed `agent-session-grep.exe` binary (sha256 `423319076286d288b954282716e3c0884c3d55cb66c9edd83eebe38149c4e073`) and is the post-rename full-corpus Gate D verification. The report matches the exact closed aggregate key sets; a raw-value scan found no Windows, Unix-home, or UNC paths, UUIDs, or complete stable entity IDs; the closed schema has no source-fingerprint, username, hostname, transcript-content, or prompt fields; stderr was empty and output remains gitignored. The earlier 2026-07-31 full run failed at `INV-SYNC-OK` (exit 5) and is recorded as-is; a 2026-08-10 subset run (137 files) also passed all six invariants. Providers remain Experimental pending independent review and owner decision. |
| `IB-SESSION-CROSS-SOURCE-001` | Ingestion handles one session whose records span multiple source files | `locally_verified` (green full-corpus run) | `docs/evidence/integration-beta/real-data-regression.md`; Domain `divergent_contextual_parents_select_per_session`; adapter relation/completeness tests; e2e `session_split_across_files_syncs_and_assembles_one_context` and `shared_message_keeps_per_session_parent_and_exact_evidence_across_split_sources` | The parent layer is implemented: stable `Message` identity/content is separate from contextual `MessagePlacement` and `MessageEdge`, session-scoped selection uses the typed graph, and synthetic/e2e coverage proves shared identities, exact placement evidence, and different parents by context. The green full-corpus run (2026-08-09T21:10:16Z, 1,242 sources, 231 sessions, 164,136 emitted, 0 skipped) passes all six invariants including session presence, context non-empty (231 sessions, 0 failures), and rebuild stability on real data — corpus-wide acceptance is now met. Provider Beta promotion remains subject to the independent review and owner decision tracked in the provider maturity matrix. |
| `CB-CI-LINUX-GNU-X64-001` | Ubuntu 22.04 GNU x64 build, direct CLI smoke, SQLite adapter tests, and storage spikes | `ci_verified` | Run `30165919066` job `Ubuntu 22.04 / GNU x64`; `.github/workflows/core-beta-evidence.yml` | The job passed on `ubuntu-22.04`. This is not proof of the proposed glibc 2.31 floor and is not a Linux distribution compatibility certification. |
| `CB-CI-MACOS-X64-001` | macOS Intel x64 build, direct CLI smoke, SQLite adapter tests, and storage spikes | `ci_verified` | Run `30165919066` job `macOS Intel / x64`; `.github/workflows/core-beta-evidence.yml` | The job passed on `macos-15-intel`, which is the first executed macOS evidence in this repository; no maintainer-owned macOS host exists. `MACOSX_DEPLOYMENT_TARGET=12.0` constrains the build setting but the run executed on macOS 15, so it does not prove execution on macOS 12. |
| `CB-CI-MACOS-ARM64-001` | macOS Apple Silicon ARM64 build, direct CLI smoke, SQLite adapter tests, and storage spikes | `ci_verified` | Run `30165919066` job `macOS Apple Silicon / ARM64`; `.github/workflows/core-beta-evidence.yml` | The job passed on `macos-15`. The hosted-runner image is not minimum-macOS certification, and no artifact from the run has been downloaded and reviewed. |
| `CB-PROD-MULTIPROCESS-001` | Production `SqliteStore::open_for_write` contention, process-kill reacquisition, durable-intent recovery, and stale-generation rejection through a process helper | `locally_verified` | `crates/agent-session-grep-adapters-sqlite/tests/process_evidence.rs`; `crates/agent-session-grep-adapters-sqlite/src/bin/sqlite_process_helper.rs` | Four production-path process tests pass on Windows x64 and WSL2 Ubuntu 22.04/glibc 2.35. The Linux result is WSL2-local evidence, not glibc 2.31 or distribution certification. |
| `CB-PROD-SNAPSHOT-API-001` | Production immutable SQLite snapshot or bundle API | `not_implemented` | `spikes/sqlite-snapshot-wal/EVIDENCE.md` | The spike proves feasibility only. |
| `CB-LINUX-MUSL-001` | `x86_64-unknown-linux-musl` release artifact and smoke | `externally_blocked` | `docs/adr/ADR-0002-platform-targets.md`; `docs/operations/external-readiness-gate.md` | The dedicated workflow intentionally covers the requested Linux GNU pair only; musl build/runtime infrastructure and an executed artifact remain outstanding. |
| `CB-GLIBC-231-001` | Linux GNU artifact certified against glibc 2.31 | `externally_blocked` | `docs/adr/ADR-0002-platform-targets.md` | The configured Ubuntu 22.04 runner uses a newer userspace and cannot certify this floor. |
| `CB-MACOS-12-001` | Runtime certification on macOS 12 for Intel and ARM64 | `externally_blocked` | `docs/adr/ADR-0002-platform-targets.md` | A deployment-target environment variable and newer hosted runners are not runtime certification on macOS 12. |
| `CB-SIGNING-001` | Windows Authenticode signing | `externally_blocked` | `docs/operations/external-readiness-gate.md` | No signing identity or credential is available; the evidence workflow uploads explicitly unsigned artifacts. |
| `CB-NOTARIZATION-001` | macOS signing and notarization | `externally_blocked` | `docs/operations/external-readiness-gate.md` | No Apple signing identity, notarization credential, or governed release run is available. |
| `RL-UNSIGNED-ARTIFACTS-001` | Tag-gated four-target unsigned release archives, synthetic smoke, SHA256SUMS, path-free provenance manifests, and Cargo metadata dependency JSON/CSV | `ci_configured_only` | `.github/workflows/release.yml`; `scripts/release/build-manifest.py`; `docs/release/rehearsal-runbook.md` | This records configured release machinery only. A named successful release run and downloaded assets are required before `ci_verified`; manifests are self-reported and not signatures, notarization, or GitHub Artifact Attestation. Workflow dispatch does not create a GitHub Release; tag publication remains an owner action. |

## What the dedicated workflow records

For each explicit runner/target pair, the workflow is configured to:

1. install Python and the Rust target, then build the release CLI with `--locked`;
2. invoke the built binary directly for `--version`, `--help`, and robot `config paths` smoke;
3. run the benchmark harness unit tests plus its synthetic `smoke` profile and report validator;
4. run the current SQLite adapter test targets, including production process evidence;
5. run the Claude and Codex provider evidence tests (golden, property, span round-trip) on that target;
6. run the open-source gate benchmark on that target and validate its manifest;
7. run the data-root locking, SQLite WAL snapshot, and SQLite source-identity feasibility spikes;
8. write an environment report containing runner labels, target triple, Rust/Cargo versions, source commit, binary size, and SHA-256;
9. upload the report, logs, and unsigned binary for seven days.

The workflow intentionally performs no publish, signing, notarization, checksum attestation, provenance publication, or release creation.

A workflow row is promoted from `ci_configured_only` to `ci_verified` only when a specific successful run of that exact job is named in `## Recorded CI run`. Promotion to `locally_verified` additionally requires evidence checked into this repository; a hosted run whose artifacts expire in 7 days does not meet that bar. No row is promoted on the basis of workflow configuration alone.

## Milestone accounting rule

A composite 0.2 cross-platform or release-readiness checkbox must remain open while any required target is only `ci_configured_only`, `ci_verified`, `externally_blocked`, or `not_implemented`. `ci_verified` is deliberately insufficient on its own: it establishes that the code builds and its tests pass on a hosted runner image, not that the artifact is signed, certified against a minimum OS, or installable on a clean machine. Smoke output may establish that a command started and returned successfully on one environment; it must not be relabeled as a formal SLO, minimum-OS certification, architecture certification, signed-release evidence, or clean-machine packaging evidence.
