# Core Alpha / Cross-platform Beta evidence manifest

> Evidence bundle pinned to source commit `88d86f4`
> (`88d86f44a0f8d4d0261aaddddb99524514e57d7b`).
>
> - status: **Draft** evidence accounting; no governance record is marked
>   Accepted by this bundle.
> - interpretation: every number here is a local evidence anchor. None of it is
>   a formal SLO, minimum-OS certification, architecture certification, or
>   release certification.
> - cross-reference: `docs/operations/core-beta-evidence-matrix.md` holds the
>   per-target status vocabulary (`locally_verified`, `ci_configured_only`,
>   `externally_blocked`, `not_implemented`).

## Executed evidence

| Evidence | Environment | Result | Reproduce |
|---|---|---|---|
| Full benchmark | Windows 11, `x86_64-pc-windows-msvc`, rustc 1.97.1, SQLite 3.53.2, 22 logical CPUs, 31.5 GB RAM, Samsung NVMe SSD, NTFS, Defender real-time on | Strengthened validator passes; startup 20+20, search/show/get 100 each, sync workloads 3 each | `python scripts/evidence/core_beta_benchmark.py run --profile full --workspace . --output-dir evidence-output --expected-commit 88d86f44a0f8d4d0261aaddddb99524514e57d7b --disk "Samsung NVMe SSD" --filesystem NTFS --antivirus-state "Windows Defender real-time protection enabled" --sqlite-version 3.53.2 --sqlite-version-source "same-commit sqlite-snapshot-wal rusqlite::version(); workspace and spike lock rusqlite 0.40.1/libsqlite3-sys 0.38.1"` |
| Production SQLite process evidence (Windows) | Windows x64, rustc 1.97.1 | 56 adapter unit tests + 4 process tests pass after independent-review fixes | `cargo test -p agent-session-grep-adapters-sqlite --all-targets` |
| Linux build/test/smoke | WSL2 Ubuntu 22.04, glibc 2.35, kernel 6.6.87.2, x86_64, rustc/cargo 1.97.1 | locked release CLI build, direct `--version` and robot `config paths` smoke, and full workspace tests pass | see `linux-wsl2-build-test-smoke.txt` |
| WAL snapshot feasibility | Windows x64, SQLite 3.53.2 | A/B/C/D pass; assertion failure exits nonzero | `cargo run --locked --release --manifest-path spikes/sqlite-snapshot-wal/Cargo.toml` |

## Full-profile benchmark headline

The authoritative raw samples are in `core-beta-benchmark-full.json`; the
Markdown file is a review projection. The harness built the measured release
binary from this workspace using `cargo build --locked --release` and records
`binary.provenance = built_by_harness_from_workspace`.

The dataset is 4000 deterministic synthetic Claude Code JSONL messages
(`contains_real_transcripts: false`), SHA-256
`8ebb21d29ce589b9a36b94819a6b4baf2cf0f6c45bf591d552e8d40967833b4e`.
The release binary SHA-256 is
`1afafcee71e5ae15cdad4b6aa382e5868faad71d1bffec641bf4207e490d1119`.

- warm startup: P50 8.44 ms, P95 11.71 ms, P99 12.99 ms (n=20)
- cold startup (best effort; OS caches not flushed): P50 14.63 ms, P95 20.35
  ms, P99 20.44 ms (n=20)
- search: P50 17.73 ms, P95 22.44 ms, P99 25.40 ms (n=100)
- show: P50 19.03 ms, P95 24.21 ms, P99 25.64 ms (n=100)
- get: P50 18.74 ms, P95 25.35 ms, P99 113.94 ms (n=100; tail outlier
  retained in raw samples)
- aggregate peak RSS: P95 1.93 MB, P99 12.00 MB, max 12.74 MB; summaries
  are recomputed from the raw per-workload samples by the validator
- initial store/source ratio: 5.11; release artifact 2,406,400 bytes
- recovery duration: `not_implemented`; clean `doctor` open time is not
  presented as recovery evidence

These values are not SLOs and must not be used as cross-machine regression
thresholds without a fixed benchmark environment and approved policy.

## Production process and source evidence

`crates/agent-session-grep-adapters-sqlite/tests/process_evidence.rs` drives
production `SqliteStore::open_for_write` through the non-user-facing helper
`crates/agent-session-grep-adapters-sqlite/src/bin/sqlite_process_helper.rs`. Recorded Windows and WSL2 Linux runs prove:

1. exactly one writer acquires the data-root lease; contender diagnostics are
   path-free;
2. killing the holder releases the OS lock without deleting `writer.lock`, and
   the next process can acquire it;
3. a durable `building` intent left by an exiting process is recovered to
   `aborted` while generation/catalog stay unchanged, and recovery is
   idempotent;
4. a stale-generation commit fails closed on the production CAS guard without
   applying the catalog row.

Independent review additionally verified and fixed two source-batch invariants:
duplicate-message errors no longer disclose provider paths, and the same wire
ID with conflicting full `StableId` metadata is rejected instead of making the
persisted FTS identity depend on input order. The equal-length replacement test
restores mtime and length so it deterministically exercises the fingerprint
branch.

## Platform accounting

- Windows x64: full benchmark, complete workspace tests, production process
  evidence, and WAL spike were executed locally at `88d86f4`.
- Linux x64: a locked release CLI build, direct binary smoke, and full workspace
  tests were executed under **WSL2 Ubuntu 22.04 / glibc 2.35** at `88d86f4`.
  This is WSL2-local build/run evidence, not glibc 2.31, minimum-OS, clean-host,
  or distribution certification.
- The four exact GitHub Actions runner/target jobs remain
  `ci_configured_only`; there is no remote run URL or downloaded artifact.
- macOS x64/ARM64, Linux musl, glibc 2.31 floor, Authenticode, Apple signing,
  and notarization were not executed and remain configured-only or externally
  blocked as recorded in the matrix.
- A production immutable SQLite snapshot/bundle API is still
  `not_implemented`; the WAL result is feasibility evidence only.

## Quality and review

The implementation was independently reviewed after the initial evidence run.
Confirmed privacy, identity-ordering, benchmark-provenance, CI, glibc wording,
and report-validation issues were fixed before this final bundle was produced.
The final closeout reruns the workspace and evidence quality gates before the
bundle commit.
