# Real-data regression

Scope: running `scripts/evidence/real_data_regression.py` against your own
Claude Code and Codex transcripts to check that ingestion, context assembly,
index rebuild, and source immutability hold their invariants on real input
instead of only on synthetic fixtures.

## Why this runs locally and stays local

Real transcripts are personal data. The authorization for this check is
narrow: **the data stays on the machine that produced it.** The harness is
built around that constraint rather than trusting the operator to redact
afterwards.

- Sources are opened read-only. The provider path never writes to a
  transcript, and `INV-SOURCES-UNCHANGED` compares every source's SHA-256
  before sync and after the full run. Fingerprints remain process-local and
  never enter the report.
- Ingestion targets a throwaway temporary data root created per run and
  deleted at the end. Your real data root is untouched.
- The report contains aggregate counts and invariant verdicts only. No
  message text, no source paths, no provider-native ids, no fingerprints, no
  usernames, no hostnames.
- Reports are written under `evidence-output/`, which is gitignored. The
  harness does not commit, push, or upload anything.

What lives in the repository is the harness, its unit tests, and an example
report produced from synthetic fixtures. Reports produced from real data do
not go into the repository.

## What this does not establish

Passing this check does not promote a provider to Beta. It closes the
"repeatable process" gap in `docs/product/PROVIDER-MATURITY-MATRIX.md` —
the procedure and the checker are auditable even though the corpus is not
shareable. The remaining gate (three-platform CI certification recorded
against a specific run) is separate. Both providers stay Experimental until
every documented gate is green.

## Prerequisites

- A release binary. Build it with
  `cargo build --locked --release -p agent-session-grep-cli`, or use an installed
  one (see `INSTALL-AND-UPGRADE.md`).
- Python 3. No third-party packages.
- One or more directories or files of `.jsonl` transcripts you are authorized
  to read.

## Run it

```
python scripts/evidence/real_data_regression.py \
  --binary target/release/agent-session-grep \
  --sources C:/data/example-transcripts \
  --out evidence-output/real-data-regression.json
```

| Flag | Meaning |
|---|---|
| `--binary <path>` | The `agent-session-grep` binary to exercise. Required. |
| `--sources <dir\|file>` | Transcript directory (searched recursively for `.jsonl`) or single file. Repeatable. |
| `--out <path>` | Report destination. Defaults under `evidence-output/`. |
| `--json` | Emit the JSON report to stdout in addition to the file. |
| `--dry-run` | Print the plan and write no file. |

Exit codes: `0` all invariants passed; `1` at least one invariant failed
(the report is still written, with `outcome: failed`); `2` usage error, such
as source arguments that matched no `.jsonl` files.

## What it exercises

Against a temporary data root, the harness first fingerprints every source,
then runs one `sync` over all collected sources, followed by `status` (catalog
count, generation, source-placement claims) plus a full catalog `list` walk,
then `context --policy mainline` for every session entity, then `index rebuild`
followed by a catalog walk and sampled `search` calls. Finally it fingerprints
every source again and compares aggregate results. All CLI calls go through
`--robot` and are read from the response envelope, not from human-readable
text. (`doctor` is not part of the harness; its runtime state report is a
separate operator command.)

`sync` runs in chunks. A source modified between its capture and the post-stage
verification — typically the live session still appending — is now **deferred**
by `sync` itself: it is dropped from that chunk's commit batch, reported through
a per-source diagnostic and the chunk's `deferred` count, and the rest of the
chunk commits. The harness therefore normally sees `ok: true` with a non-zero
`deferred`, not a failed chunk. The retry path is still in place for a chunk
that does fail with `source_changed` (a single-source chunk has nothing else to
carry the run): the harness waits `SYNC_CHANGED_BACKOFF_S` (3 seconds) and
retries the same chunk, up to `SYNC_CHANGED_RETRIES` (3) attempts. `sync` is
idempotent and chunk-scoped, so a retried chunk commits nothing from the failed
attempt. Other errors are not retried: a persistent `source_changed` or any
other failure is reported as-is in the report and the run finishes with the
invariants it could still evaluate.

## The seven invariants

| id | What it asserts | What a failure means |
|---|---|---|
| `INV-SYNC-OK` | Every `sync` chunk reports `ok: true` and the run emits more than zero source occurrences. | Ingestion failed outright, or every source was rejected. Read the envelope's error code. |
| `INV-NO-PARSE-LOSS` | Provider-emitted source occurrences equal persisted source-placement claims, and `skipped == 0`. | An emitted occurrence lacks a durable claim, claims were duplicated, or parsing skipped input. Stable Message de-duplication is not loss. |
| `INV-SESSION-PRESENT` | At least one `ses_v1_` entity exists, and no more than one per source file. | Session attribution is missing or duplicated. |
| `INV-CONTEXT-NONEMPTY` | Every context request succeeds; a session whose catalog projection owns messages assembles at least one. A verified zero-placement session may return an empty message list. | Context assembly cannot reach messages the session owns, or the request failed. An `internal` error is a bug signal, not bad input. |
| `INV-SPAN-COVERAGE` | Every evidence span from this ingest has `precision == "byte"`. | Byte offsets were not recorded. Freshly ingested sources should always have them; `unknown` precision belongs to pre-v6 rows, which a fresh temporary store cannot contain. |
| `INV-REBUILD-STABLE` | Catalog counts before and after `index rebuild` match, and sampled searches return the same number of hits. | Rebuild is not a faithful reprojection of the catalog. See `rebuild-and-migration-runbook.md`. |
| `INV-SOURCES-UNCHANGED` | Every collected source has the same SHA-256 before `sync` and after the full harness run. | A source was changed, deleted, or became unreadable while the harness ran. The detail contains only checked, unchanged, and changed counts. |

## Reading the report

The JSON report is the authority; the Markdown form is a human projection of
the same fields.

| Field | Meaning |
|---|---|
| `schema_version`, `kind` | Report format version and `real-data-regression`. |
| `generated_at_utc` | Run timestamp, UTC. |
| `binary` | Basename, version, and SHA-256 of the exercised binary. The basename only — no directory. |
| `environment` | OS family, OS release, Python version. |
| `corpus` | Number of source files and total bytes. Counts and sizes only, never names. |
| `totals` | De-duplicated stable Messages, sessions, documents, and total catalog entities. Message count is a census, not the no-loss denominator. |
| `role_distribution` | Message count per role. |
| `evidence_precision` | Span count per precision tier (`byte`, `line`, `record`, `unknown`). |
| `invariants` | One entry per invariant: `id`, `passed`, and an aggregate-only `detail`. `INV-NO-PARSE-LOSS` records emitted occurrences, source-placement claims, skipped records, and the separate stable Message census. `INV-SOURCES-UNCHANGED` records checked, unchanged, and changed source counts only. |
| `outcome` | `passed` or `failed`. |

## When it fails

Read `invariants` first: the failing entry names the check, and its `detail`
carries the aggregate numbers that disagreed. That is intentionally all it
carries, so triage happens against your local store rather than against the
report.

To investigate, re-run the same steps by hand on a temporary data root and
inspect the specific session. `context --robot` surfaces `warnings` and the
error envelope carries a stable `code`; the exit code follows the same
mapping as every other command (`2` invalid request or cursor, `4` not found,
`5` source I/O or source changed, `6` catalog error or writer busy, `7`
provider error, `9` schema incompatible, `70` internal, `10` partial result
after budget truncation).

Before sharing anything, check it. A hand-run `context` or `search` prints
real message text — that output is not covered by the harness's privacy
guarantees. Only the generated report is.
