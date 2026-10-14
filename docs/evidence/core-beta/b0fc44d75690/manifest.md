# Current-source baseline bundle manifest

- Suite ID: `current-source-20261014-b0fc44d75690`
- Measured source (S): `b0fc44d756909cc840050351dd1329896a8edf75`
- Harness/checker: `scripts/evidence/core_beta_benchmark.py` executed from S
  itself (H=S), harness SHA-256
  `aeb23f909de805f507f45c1c61a20cf940a111ee962a0c6d6cd4ae37a49f39f8`.
- Protocol: `agent-session-grep.core-beta-benchmark/v1` plus optional
  `baseline` extension `agent-session-grep.current-source-baseline/v1`.
- Environment: Windows 10.0.22631, `x86_64-pc-windows-msvc`, Intel Core
  Ultra 7 155H, 22 logical CPUs, 31.5 GiB RAM, NTFS on NVMe SSD, Microsoft
  Defender Antivirus with real-time protection enabled.
- Toolchain: rustc 1.97.1; SQLite 3.53.2 derived from locked bundled
  `libsqlite3-sys` source and this build's linkage receipt; no CLI runtime
  version query. Python 3.10.11 drove the harness.

## Frozen build

- Binary B SHA-256:
  `39049bfd9340ce4ade9fc289b1ca89ab8af40e1d94942df7e0df565e791abe8e`
- Binary size: 7,824,896 bytes
- Build receipt SHA-256:
  `88b3b1e9f03531ee51b074a98c0863ed95f13e16aa2cd91ed8f7d40da97888b1`
- Build: `cargo build --locked --release -p agent-session-grep-cli`
  before the shared suite deadline; runs 2 and 3 verified and reused B
  without rebuilding. Run 1 reports `built_by_harness_from_workspace`;
  runs 2 and 3 keep the `caller_supplied_prebuilt` caveat and the
  originating receipt linkage.

## Reports

| Run | Scale order | Report SHA-256 | Report bytes | Markdown SHA-256 |
| --- | --- | --- | ---: | --- |
| 01 | small/medium/large | `76996fba2cbbd1fe305859371429de9c485cdae610bee2de3b5654fdc28d3623` | 5,681,417 | `e7e1ec3378a38a21261a777477cca3a380ef6dd1efb6462e6a9e29dbf08811b6` |
| 02 | medium/large/small | `77d6f7d586df524170681ea65821f840b83411970ee7ee908c4734cc5d47057b` | 5,682,021 | `e5bbb7eb68013e56cd3de04032ee2ed131cb49d367bf26e7d836fc24701c8b30` |
| 03 | large/small/medium | `5f3031d6895ffb886328d97335f485424c60252e44f4fb4c7f118c40aa8bb4e0` | 5,681,712 | `965c1c7509783892328ac25cec528ccb58686e8ff2b184678924a6a50588d335` |

Every Markdown file is the byte-exact projection of its validated JSON from
the S renderer. Each report keeps raw samples for all measured observations;
summaries and throughput ratios are recomputed by the validator.

## Measurement window and bounds

- Suite deadline started after run 1 froze B and its receipt:
  `2026-10-14T12:50:05.949642Z`.
- Run 1 completed `2026-10-14T13:00:00.493795Z`; run 2 completed
  `2026-10-14T13:30:50.276567Z`; run 3 report completed
  `2026-10-14T13:41:23.011842Z`, followed by the separate trace trial.
- Total measured suite wall: about 52.7 minutes, within the approved
  60-minute and 300-second-per-child bounds. Startup, sync, query and
  context samples all remained below the per-child limit.
- The shared suite deadline started only after run 1 froze B and its
  receipt; runs 2 and 3 reused that build without Cargo. Suite wall is
  measured from that deadline to the end of the run-3 trace trial.

## Failed attempts (disclosed, not part of this bundle)

- `07f75b0fe5aadb...`: zero-sample attempt stopped in build provenance
  because MSVC emits both `sqlite3.lib` and `libsqlite3.a` aliases; fixed
  by the `6dc0e55792db` commit before any measurement.
- `6dc0e55792db` suite: 3,169 successful observations failed final
  anchor-size linkage because the post-read footprint legitimately differs
  from the shrink-sync footprint; fixed by the `b0fc44d75690` commit. Its
  589.4 seconds of measured wall time are not suite time and are excluded
  from this bundle. Including that disclosed failed attempt, total local
  measurement wall across both attempts is about 62.5 minutes; the
  qualified three-run suite bound remains 60 minutes and this suite used
  52.7 of them.

## Trace

One separate 50,000-message initial/noop/shrink trial ran after run 3 with
`ASG_INDEX_TRACE` enabled only in its own child environments. Trace output
parsed and validated; status `available`. Raw traces stay private. The
reviewed stage aggregates show the dominant single nested stage on the
50,000-message initial sync is transaction commit, followed by relation
upserts and session projection; nested scopes overlap and must not be
summed. Instrumentation-enabled observations never enter primary latency.

## Reproduction

```powershell
$baselineSource = 'b0fc44d756909cc840050351dd1329896a8edf75'
$baselineActual = (git rev-parse HEAD).Trim()
if ($baselineActual -ne $baselineSource) { throw 'Use the clean measured source S.' }
$baselineSuite = 'current-source-20261014-b0fc44d75690'
foreach ($baselineRun in 1..3) {
    $baselineOutput = 'evidence-output/current-baseline/run-{0:D2}' -f $baselineRun
    python -B scripts/evidence/core_beta_benchmark.py run `
      --profile full --baseline-run $baselineRun --suite-id $baselineSuite `
      --workspace . --output-dir $baselineOutput `
      --expected-commit $baselineSource `
      --disk 'NVMe SSD SAMSUNG MZVL81T0HELB-00BTW' --filesystem NTFS `
      --antivirus-state 'Microsoft Defender Antivirus and real-time protection enabled' `
      --sqlite-version 3.53.2 `
      --sqlite-version-source 'locked bundled source + this build linkage; no direct CLI runtime query'
    if ($LASTEXITCODE -ne 0) { throw 'Baseline attempt failed; retain its evidence.' }
}
python -B scripts/evidence/core_beta_benchmark.py validate-baseline `
  evidence-output/current-baseline/run-01/core-beta-benchmark-full.json `
  evidence-output/current-baseline/run-02/core-beta-benchmark-full.json `
  evidence-output/current-baseline/run-03/core-beta-benchmark-full.json
```

## Noise and limitations

Cross-run median spread above 15 percent was recorded for several series:
anchor get/search cjk/search token, cold startup, anchor and 10k initial
sync, anchor shrink, 50k shrink, some context and noop series. These are
retained noise observations, not gates; small noop series vary widely in
absolute terms while remaining milliseconds. Single-host Windows coverage,
OS-cache-uncontrolled cold startup and limited tail resolution for
20-sample startup and 3-sample sync series remain explicit limitations.
This bundle is local evidence, not SLO, cross-platform, release or
recall certification.
