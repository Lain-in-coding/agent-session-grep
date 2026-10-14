# Core/Beta benchmark evidence

- Evidence status: `locally_verified`
- Profile: `full`
- Commit: `b0fc44d756909cc840050351dd1329896a8edf75`
- OS/target: `windows` / `x86_64-pc-windows-msvc`
- SQLite build-derived version: `3.53.2` (locked bundled source + this build linkage; no direct CLI runtime query)
- Dataset: 4000 synthetic messages, SHA-256 `8ebb21d29ce589b9a36b94819a6b4baf2cf0f6c45bf591d552e8d40967833b4e`
- Binary SHA-256: `39049bfd9340ce4ade9fc289b1ca89ab8af40e1d94942df7e0df565e791abe8e`
- Binary provenance: `built_by_harness_from_workspace`

These results are local evidence anchors, not formal SLOs or release certification.

## Metrics

| Metric | Samples | P50 | P95 | P99 | Mean | Sample stddev |
|---|---:|---:|---:|---:|---:|---:|
| `cli_startup_cold_latency_ms` | 20 | 22.759 | 40.411 | 47.558 | 25.961 | 7.262 |
| `cli_startup_warm_latency_ms` | 20 | 8.639 | 12.037 | 36.831 | 10.567 | 6.316 |
| `initial_sync_latency_ms` | 3 | 754.250 | 813.491 | 813.491 | 764.256 | 45.073 |
| `noop_sync_latency_ms` | 3 | 17.369 | 18.683 | 18.683 | 17.784 | 0.780 |
| `shrink_sync_latency_ms` | 3 | 619.855 | 650.104 | 650.104 | 627.064 | 20.413 |
| `search_latency_ms` | 100 | 71.163 | 121.758 | 139.608 | 77.896 | 19.941 |
| `show_latency_ms` | 100 | 15.828 | 23.618 | 39.877 | 17.081 | 4.634 |
| `get_latency_ms` | 100 | 14.428 | 21.934 | 37.927 | 15.627 | 4.654 |
| `initial_index_throughput_mb_s` | 3 | 1.419 | 1.476 | 1.476 | 1.403 | 0.081 |

## Sizes

- Release artifact: 7824896 bytes
- Synthetic source: 1122164 bytes
- Store after initial sync including sidecars: 19656704 bytes
- Store after shrink including sidecars: 19689472 bytes
- Store/source ratio: 17.516784

## Recovery

- Status: `not_implemented`
- Reason: The production CLI exposes recovery on open but no fault-injection command; a clean doctor open is not recovery evidence.

## Limitations

- These local measurements are evidence anchors, not formal SLOs or release certification.
- Cold startup uses a fresh copy of the release binary per sample; the harness does not flush OS filesystem caches.
- Startup measures process launch through --version completion, not an interactive readiness signal.
- Peak RSS uses the Windows process peak API where available; Linux /proc and macOS ps are sampled every 100 ms, so short-lived peaks may be missed.
- Storage size includes the database and present SQLite sidecars after commands exit; no explicit checkpoint command is available.
- Recovery duration is unavailable without a production fault-injection entry point and is not inferred from a clean open.
- SQLite version is derived from the locked bundled source and this build's linkage receipt; no CLI runtime version query was performed.

## Current-source baseline

- Suite/run: `current-source-20261014-b0fc44d75690` / 1 of 3
- Measured source and checker: `b0fc44d756909cc840050351dd1329896a8edf75`
- Harness SHA-256: `aeb23f909de805f507f45c1c61a20cf940a111ee962a0c6d6cd4ae37a49f39f8`
- Originating build receipt SHA-256: `88b3b1e9f03531ee51b074a98c0863ed95f13e16aa2cd91ed8f7d40da97888b1`
- Binary use: `built_in_run_1`; linkage is not independently attested.
- UTC interval: 2026-10-14T12:50:06.127662Z to 2026-10-14T13:00:00.493795Z
- Corrected timing: `process-wall-before-observer/v1`; legacy metrics above retain `legacy-wall-with-observer/v1`.
- Anchor queries use 2,000 post-shrink Messages; scale queries use intact 2k/10k/50k corpora.
- Anchor store at final shrink-sync exit: 19656704 bytes; after search/show/get/doctor: 19689472 bytes (legacy final size).
- Trace is disabled for primary samples. A separate local trial follows primary run 3.
- P50/P95/MAD below use persisted corrected wall times. Response bytes include the final LF.

| Workload | Operation/class | Samples | P50 ms | P95 ms | MAD ms | P50 bytes | RSS observations |
|---|---|---:|---:|---:|---:|---:|---:|
| `anchor` | `startup_warm` | 20 | 8.561 | 11.970 | 0.579 | 25.000 | 20 |
| `anchor` | `startup_cold` | 20 | 22.698 | 40.334 | 1.302 | 25.000 | 20 |
| `anchor` | `sync/initial` | 3 | 754.178 | 813.428 | 29.405 | 524.000 | 3 |
| `anchor` | `sync/noop` | 3 | 17.295 | 18.606 | 0.086 | 516.000 | 3 |
| `anchor` | `sync/shrink` | 3 | 619.762 | 649.981 | 8.646 | 524.000 | 3 |
| `anchor` | `search/token` | 20 | 78.959 | 121.628 | 8.582 | 10511.000 | 20 |
| `anchor` | `search/latin` | 20 | 71.414 | 111.896 | 4.416 | 10303.000 | 20 |
| `anchor` | `search/cjk` | 20 | 71.382 | 102.545 | 7.713 | 10343.000 | 20 |
| `anchor` | `search/path` | 20 | 66.939 | 103.167 | 4.066 | 9943.000 | 20 |
| `anchor` | `search/identifier` | 20 | 63.927 | 120.849 | 6.821 | 10503.000 | 20 |
| `anchor` | `show` | 100 | 15.755 | 23.512 | 1.172 | 931.000 | 100 |
| `anchor` | `get` | 100 | 14.356 | 21.859 | 1.462 | 984.000 | 100 |
| `scale-2000` | `sync/initial` | 3 | 416.739 | 449.120 | 19.654 | 524.000 | 3 |
| `scale-2000` | `sync/noop` | 3 | 15.277 | 15.730 | 0.453 | 516.000 | 3 |
| `scale-2000` | `sync/shrink` | 3 | 350.669 | 417.496 | 37.442 | 524.000 | 3 |
| `scale-2000` | `search/token` | 100 | 71.066 | 105.121 | 7.606 | 10522.000 | 100 |
| `scale-2000` | `search/latin` | 100 | 64.177 | 93.353 | 7.912 | 10303.000 | 100 |
| `scale-2000` | `search/cjk` | 100 | 66.615 | 99.889 | 9.248 | 10343.000 | 100 |
| `scale-2000` | `search/path` | 100 | 63.762 | 100.742 | 10.178 | 9943.000 | 100 |
| `scale-2000` | `search/identifier` | 100 | 59.790 | 99.308 | 4.711 | 10503.000 | 100 |
| `scale-2000` | `show` | 100 | 14.030 | 40.188 | 1.531 | 924.000 | 100 |
| `scale-2000` | `get` | 100 | 12.666 | 36.467 | 1.464 | 976.000 | 100 |
| `scale-2000` | `context/mainline` | 100 | 18.285 | 45.303 | 1.259 | 21678.000 | 100 |
| `scale-2000` | `context/full` | 100 | 32.013 | 56.495 | 2.716 | 241333.000 | 100 |
| `scale-10000` | `sync/initial` | 3 | 1889.734 | 1946.220 | 56.486 | 528.000 | 3 |
| `scale-10000` | `sync/noop` | 3 | 23.877 | 23.918 | 0.041 | 518.000 | 3 |
| `scale-10000` | `sync/shrink` | 3 | 1580.968 | 2149.850 | 166.870 | 525.000 | 3 |
| `scale-10000` | `search/token` | 100 | 149.279 | 226.017 | 17.021 | 10507.000 | 100 |
| `scale-10000` | `search/latin` | 100 | 110.047 | 159.102 | 17.514 | 10301.000 | 100 |
| `scale-10000` | `search/cjk` | 100 | 95.299 | 155.041 | 16.191 | 10343.000 | 100 |
| `scale-10000` | `search/path` | 100 | 97.124 | 154.901 | 16.290 | 9943.000 | 100 |
| `scale-10000` | `search/identifier` | 100 | 95.334 | 149.459 | 13.726 | 10503.000 | 100 |
| `scale-10000` | `show` | 100 | 13.015 | 28.770 | 1.214 | 839.000 | 100 |
| `scale-10000` | `get` | 100 | 11.919 | 20.617 | 0.797 | 887.000 | 100 |
| `scale-10000` | `context/mainline` | 100 | 24.278 | 46.935 | 2.458 | 21679.000 | 100 |
| `scale-10000` | `context/full` | 100 | 35.171 | 50.632 | 2.284 | 241333.000 | 100 |
| `scale-50000` | `sync/initial` | 3 | 10122.897 | 10426.746 | 303.849 | 530.000 | 3 |
| `scale-50000` | `sync/noop` | 3 | 80.700 | 101.687 | 11.124 | 519.000 | 3 |
| `scale-50000` | `sync/shrink` | 3 | 9943.210 | 11179.567 | 1236.357 | 529.000 | 3 |
| `scale-50000` | `search/token` | 100 | 552.367 | 803.595 | 29.843 | 10507.000 | 100 |
| `scale-50000` | `search/latin` | 100 | 375.356 | 481.103 | 26.033 | 10302.000 | 100 |
| `scale-50000` | `search/cjk` | 100 | 171.621 | 222.824 | 16.116 | 10344.000 | 100 |
| `scale-50000` | `search/path` | 100 | 171.645 | 226.436 | 13.229 | 9944.000 | 100 |
| `scale-50000` | `search/identifier` | 100 | 166.165 | 217.718 | 14.049 | 10504.000 | 100 |
| `scale-50000` | `show` | 100 | 12.356 | 17.548 | 0.894 | 839.000 | 100 |
| `scale-50000` | `get` | 100 | 11.616 | 15.225 | 0.747 | 887.000 | 100 |
| `scale-50000` | `context/mainline` | 100 | 35.441 | 50.748 | 2.337 | 21679.000 | 100 |
| `scale-50000` | `context/full` | 100 | 49.499 | 66.928 | 3.159 | 241333.000 | 100 |

### Corpus and initial-sync throughput

| Workload | Initial Messages | Query Messages | Shrink Messages | Median Messages/s | Median MiB/s |
|---|---:|---:|---:|---:|---:|
| `anchor` | 4000 | 2000 | 2000 | 5303.786 | 1.419 |
| `scale-2000` | 2000 | 2000 | 1000 | 4799.170 | 1.284 |
| `scale-10000` | 10000 | 10000 | 5000 | 5291.750 | 1.416 |
| `scale-50000` | 50000 | 50000 | 25000 | 4939.297 | 1.321 |

### Baseline limitations

- Synthetic positive first-page queries are not recall certification.
- show/get are single-entity reads; context uses one generator-selected Session per scale.
- Twenty startup and three sync samples have limited tail resolution.
- Periodic process RSS is an approximate observation; absent observations remain null.
- CLI duration is an integer-ms pre-render observation, not pure engine time.
- Source SHA-256 is independently recomputed; native fingerprint alignment is checked across scan, document and evidence.
- Boundary resource checks are guardrails, not OS quotas; process creation is not preemptible.
- Build-derived SQLite evidence is not a CLI runtime version query or independent binary attestation.
