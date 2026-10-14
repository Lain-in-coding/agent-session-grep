# Core/Beta benchmark evidence

- Evidence status: `locally_verified`
- Profile: `full`
- Commit: `b0fc44d756909cc840050351dd1329896a8edf75`
- OS/target: `windows` / `x86_64-pc-windows-msvc`
- SQLite build-derived version: `3.53.2` (locked bundled source + this build linkage; no direct CLI runtime query)
- Dataset: 4000 synthetic messages, SHA-256 `8ebb21d29ce589b9a36b94819a6b4baf2cf0f6c45bf591d552e8d40967833b4e`
- Binary SHA-256: `39049bfd9340ce4ade9fc289b1ca89ab8af40e1d94942df7e0df565e791abe8e`
- Binary provenance: `caller_supplied_prebuilt`

These results are local evidence anchors, not formal SLOs or release certification.

## Metrics

| Metric | Samples | P50 | P95 | P99 | Mean | Sample stddev |
|---|---:|---:|---:|---:|---:|---:|
| `cli_startup_cold_latency_ms` | 20 | 28.086 | 34.602 | 35.797 | 28.444 | 3.675 |
| `cli_startup_warm_latency_ms` | 20 | 8.794 | 17.314 | 36.288 | 10.912 | 6.480 |
| `initial_sync_latency_ms` | 3 | 843.243 | 1298.014 | 1298.014 | 988.325 | 268.376 |
| `noop_sync_latency_ms` | 3 | 17.740 | 41.642 | 41.642 | 25.229 | 14.233 |
| `shrink_sync_latency_ms` | 3 | 773.445 | 795.738 | 795.738 | 718.038 | 115.812 |
| `search_latency_ms` | 100 | 74.425 | 106.160 | 114.778 | 77.746 | 13.875 |
| `show_latency_ms` | 100 | 15.708 | 32.834 | 40.318 | 18.040 | 6.676 |
| `get_latency_ms` | 100 | 16.267 | 29.039 | 47.967 | 18.368 | 6.949 |
| `initial_index_throughput_mb_s` | 3 | 1.269 | 1.299 | 1.299 | 1.131 | 0.266 |

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
- The measured binary was caller-supplied; its hash is authoritative, but source-to-binary linkage is not independently attested.
- SQLite version is derived from the locked bundled source and this build's linkage receipt; no CLI runtime version query was performed.

## Current-source baseline

- Suite/run: `current-source-20261014-b0fc44d75690` / 2 of 3
- Measured source and checker: `b0fc44d756909cc840050351dd1329896a8edf75`
- Harness SHA-256: `aeb23f909de805f507f45c1c61a20cf940a111ee962a0c6d6cd4ae37a49f39f8`
- Originating build receipt SHA-256: `88b3b1e9f03531ee51b074a98c0863ed95f13e16aa2cd91ed8f7d40da97888b1`
- Binary use: `reused_run_1_receipt`; linkage is not independently attested.
- UTC interval: 2026-10-14T13:20:41.772091Z to 2026-10-14T13:30:50.276567Z
- Corrected timing: `process-wall-before-observer/v1`; legacy metrics above retain `legacy-wall-with-observer/v1`.
- Anchor queries use 2,000 post-shrink Messages; scale queries use intact 2k/10k/50k corpora.
- Anchor store at final shrink-sync exit: 19656704 bytes; after search/show/get/doctor: 19689472 bytes (legacy final size).
- Trace is disabled for primary samples. A separate local trial follows primary run 3.
- P50/P95/MAD below use persisted corrected wall times. Response bytes include the final LF.

| Workload | Operation/class | Samples | P50 ms | P95 ms | MAD ms | P50 bytes | RSS observations |
|---|---|---:|---:|---:|---:|---:|---:|
| `anchor` | `startup_warm` | 20 | 8.735 | 17.213 | 1.066 | 25.000 | 20 |
| `anchor` | `startup_cold` | 20 | 28.001 | 34.465 | 2.661 | 25.000 | 20 |
| `anchor` | `sync/initial` | 3 | 843.146 | 1297.885 | 19.503 | 524.000 | 3 |
| `anchor` | `sync/noop` | 3 | 17.629 | 41.557 | 1.437 | 516.000 | 3 |
| `anchor` | `sync/shrink` | 3 | 773.320 | 795.656 | 22.336 | 524.000 | 3 |
| `anchor` | `search/token` | 20 | 85.655 | 114.671 | 8.759 | 10511.000 | 20 |
| `anchor` | `search/latin` | 20 | 72.361 | 92.354 | 5.590 | 10303.000 | 20 |
| `anchor` | `search/cjk` | 20 | 67.673 | 106.075 | 3.562 | 10343.000 | 20 |
| `anchor` | `search/path` | 20 | 70.833 | 87.413 | 6.689 | 9943.000 | 20 |
| `anchor` | `search/identifier` | 20 | 70.021 | 107.780 | 7.435 | 10503.000 | 20 |
| `anchor` | `show` | 100 | 15.623 | 32.719 | 1.821 | 932.000 | 100 |
| `anchor` | `get` | 100 | 16.182 | 28.880 | 2.054 | 984.000 | 100 |
| `scale-10000` | `sync/initial` | 3 | 2063.676 | 2343.507 | 162.533 | 528.000 | 3 |
| `scale-10000` | `sync/noop` | 3 | 24.220 | 38.656 | 3.183 | 518.000 | 3 |
| `scale-10000` | `sync/shrink` | 3 | 1616.694 | 1686.428 | 19.645 | 525.000 | 3 |
| `scale-10000` | `search/token` | 100 | 143.476 | 200.068 | 16.476 | 10507.000 | 100 |
| `scale-10000` | `search/latin` | 100 | 109.231 | 152.390 | 16.372 | 10301.000 | 100 |
| `scale-10000` | `search/cjk` | 100 | 93.582 | 151.800 | 14.110 | 10343.000 | 100 |
| `scale-10000` | `search/path` | 100 | 91.278 | 149.202 | 13.048 | 9943.000 | 100 |
| `scale-10000` | `search/identifier` | 100 | 94.710 | 139.796 | 11.427 | 10503.000 | 100 |
| `scale-10000` | `show` | 100 | 13.184 | 23.062 | 1.220 | 839.000 | 100 |
| `scale-10000` | `get` | 100 | 14.315 | 27.288 | 1.692 | 887.000 | 100 |
| `scale-10000` | `context/mainline` | 100 | 23.248 | 37.068 | 2.126 | 21679.000 | 100 |
| `scale-10000` | `context/full` | 100 | 36.282 | 57.819 | 3.162 | 241333.000 | 100 |
| `scale-50000` | `sync/initial` | 3 | 9440.515 | 10035.675 | 595.160 | 529.000 | 3 |
| `scale-50000` | `sync/noop` | 3 | 72.725 | 340.221 | 2.973 | 519.000 | 3 |
| `scale-50000` | `sync/shrink` | 3 | 9508.995 | 11162.956 | 1299.111 | 529.000 | 3 |
| `scale-50000` | `search/token` | 100 | 608.956 | 776.758 | 52.236 | 10507.000 | 100 |
| `scale-50000` | `search/latin` | 100 | 430.174 | 540.965 | 45.836 | 10302.000 | 100 |
| `scale-50000` | `search/cjk` | 100 | 196.148 | 247.020 | 19.970 | 10344.000 | 100 |
| `scale-50000` | `search/path` | 100 | 185.240 | 257.808 | 20.139 | 9944.000 | 100 |
| `scale-50000` | `search/identifier` | 100 | 185.912 | 259.244 | 24.112 | 10504.000 | 100 |
| `scale-50000` | `show` | 100 | 14.289 | 23.710 | 2.093 | 839.000 | 100 |
| `scale-50000` | `get` | 100 | 16.527 | 28.946 | 3.083 | 887.000 | 100 |
| `scale-50000` | `context/mainline` | 100 | 45.978 | 63.296 | 4.863 | 21679.000 | 100 |
| `scale-50000` | `context/full` | 100 | 61.141 | 89.316 | 6.309 | 241333.000 | 100 |
| `scale-2000` | `sync/initial` | 3 | 393.445 | 400.040 | 6.595 | 524.000 | 3 |
| `scale-2000` | `sync/noop` | 3 | 24.192 | 40.044 | 7.500 | 516.000 | 3 |
| `scale-2000` | `sync/shrink` | 3 | 379.494 | 471.232 | 34.233 | 524.000 | 3 |
| `scale-2000` | `search/token` | 100 | 79.090 | 109.556 | 9.212 | 10522.000 | 100 |
| `scale-2000` | `search/latin` | 100 | 71.300 | 101.144 | 7.754 | 10303.000 | 100 |
| `scale-2000` | `search/cjk` | 100 | 68.572 | 99.039 | 9.487 | 10343.000 | 100 |
| `scale-2000` | `search/path` | 100 | 67.986 | 97.797 | 8.155 | 9943.000 | 100 |
| `scale-2000` | `search/identifier` | 100 | 67.289 | 97.214 | 7.437 | 10503.000 | 100 |
| `scale-2000` | `show` | 100 | 17.968 | 29.798 | 2.147 | 924.000 | 100 |
| `scale-2000` | `get` | 100 | 15.724 | 38.352 | 1.404 | 976.000 | 100 |
| `scale-2000` | `context/mainline` | 100 | 23.233 | 34.916 | 3.467 | 21678.000 | 100 |
| `scale-2000` | `context/full` | 100 | 40.096 | 67.338 | 6.345 | 241333.000 | 100 |

### Corpus and initial-sync throughput

| Workload | Initial Messages | Query Messages | Shrink Messages | Median Messages/s | Median MiB/s |
|---|---:|---:|---:|---:|---:|
| `anchor` | 4000 | 2000 | 2000 | 4744.139 | 1.269 |
| `scale-10000` | 10000 | 10000 | 5000 | 4845.722 | 1.296 |
| `scale-50000` | 50000 | 50000 | 25000 | 5296.321 | 1.417 |
| `scale-2000` | 2000 | 2000 | 1000 | 5083.301 | 1.360 |

### Baseline limitations

- Synthetic positive first-page queries are not recall certification.
- show/get are single-entity reads; context uses one generator-selected Session per scale.
- Twenty startup and three sync samples have limited tail resolution.
- Periodic process RSS is an approximate observation; absent observations remain null.
- CLI duration is an integer-ms pre-render observation, not pure engine time.
- Source SHA-256 is independently recomputed; native fingerprint alignment is checked across scan, document and evidence.
- Boundary resource checks are guardrails, not OS quotas; process creation is not preemptible.
- Build-derived SQLite evidence is not a CLI runtime version query or independent binary attestation.
