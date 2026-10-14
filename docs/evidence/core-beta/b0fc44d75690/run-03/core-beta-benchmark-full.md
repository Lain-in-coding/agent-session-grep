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
| `cli_startup_cold_latency_ms` | 20 | 35.689 | 60.910 | 69.874 | 41.326 | 12.235 |
| `cli_startup_warm_latency_ms` | 20 | 9.254 | 34.773 | 35.718 | 13.331 | 9.441 |
| `initial_sync_latency_ms` | 3 | 719.153 | 1443.697 | 1443.697 | 952.571 | 425.501 |
| `noop_sync_latency_ms` | 3 | 18.066 | 31.740 | 31.740 | 22.295 | 8.194 |
| `shrink_sync_latency_ms` | 3 | 658.500 | 820.244 | 820.244 | 708.239 | 97.201 |
| `search_latency_ms` | 100 | 66.375 | 93.497 | 111.789 | 69.547 | 13.610 |
| `show_latency_ms` | 100 | 12.588 | 17.367 | 38.022 | 13.515 | 4.118 |
| `get_latency_ms` | 100 | 12.783 | 24.149 | 38.475 | 14.429 | 5.411 |
| `initial_index_throughput_mb_s` | 3 | 1.488 | 1.540 | 1.540 | 1.257 | 0.447 |

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

- Suite/run: `current-source-20261014-b0fc44d75690` / 3 of 3
- Measured source and checker: `b0fc44d756909cc840050351dd1329896a8edf75`
- Harness SHA-256: `aeb23f909de805f507f45c1c61a20cf940a111ee962a0c6d6cd4ae37a49f39f8`
- Originating build receipt SHA-256: `88b3b1e9f03531ee51b074a98c0863ed95f13e16aa2cd91ed8f7d40da97888b1`
- Binary use: `reused_run_1_receipt`; linkage is not independently attested.
- UTC interval: 2026-10-14T13:30:54.731162Z to 2026-10-14T13:41:23.011842Z
- Corrected timing: `process-wall-before-observer/v1`; legacy metrics above retain `legacy-wall-with-observer/v1`.
- Anchor queries use 2,000 post-shrink Messages; scale queries use intact 2k/10k/50k corpora.
- Anchor store at final shrink-sync exit: 19656704 bytes; after search/show/get/doctor: 19689472 bytes (legacy final size).
- Trace is disabled for primary samples. A separate local trial follows primary run 3.
- P50/P95/MAD below use persisted corrected wall times. Response bytes include the final LF.

| Workload | Operation/class | Samples | P50 ms | P95 ms | MAD ms | P50 bytes | RSS observations |
|---|---|---:|---:|---:|---:|---:|---:|
| `anchor` | `startup_warm` | 20 | 9.191 | 34.709 | 0.942 | 25.000 | 20 |
| `anchor` | `startup_cold` | 20 | 35.610 | 60.819 | 3.215 | 25.000 | 20 |
| `anchor` | `sync/initial` | 3 | 719.087 | 1443.577 | 24.291 | 524.000 | 3 |
| `anchor` | `sync/noop` | 3 | 18.006 | 31.599 | 1.020 | 516.000 | 3 |
| `anchor` | `sync/shrink` | 3 | 658.437 | 819.788 | 12.541 | 524.000 | 3 |
| `anchor` | `search/token` | 20 | 71.157 | 95.957 | 4.405 | 10511.000 | 20 |
| `anchor` | `search/latin` | 20 | 67.686 | 93.424 | 7.947 | 10303.000 | 20 |
| `anchor` | `search/cjk` | 20 | 60.816 | 77.510 | 3.769 | 10343.000 | 20 |
| `anchor` | `search/path` | 20 | 71.873 | 87.735 | 8.951 | 9943.000 | 20 |
| `anchor` | `search/identifier` | 20 | 60.895 | 101.158 | 6.212 | 10503.000 | 20 |
| `anchor` | `show` | 100 | 12.518 | 17.252 | 0.646 | 932.000 | 100 |
| `anchor` | `get` | 100 | 12.703 | 24.089 | 0.848 | 983.000 | 100 |
| `scale-50000` | `sync/initial` | 3 | 10577.147 | 10756.872 | 179.725 | 530.000 | 3 |
| `scale-50000` | `sync/noop` | 3 | 77.555 | 109.382 | 0.309 | 519.000 | 3 |
| `scale-50000` | `sync/shrink` | 3 | 13726.753 | 16912.470 | 2600.208 | 530.000 | 3 |
| `scale-50000` | `search/token` | 100 | 617.148 | 777.299 | 62.306 | 10507.000 | 100 |
| `scale-50000` | `search/latin` | 100 | 428.881 | 588.604 | 55.649 | 10302.000 | 100 |
| `scale-50000` | `search/cjk` | 100 | 190.987 | 246.951 | 22.097 | 10344.000 | 100 |
| `scale-50000` | `search/path` | 100 | 188.199 | 259.857 | 21.716 | 9944.000 | 100 |
| `scale-50000` | `search/identifier` | 100 | 187.812 | 260.003 | 28.370 | 10504.000 | 100 |
| `scale-50000` | `show` | 100 | 13.647 | 35.200 | 1.846 | 839.000 | 100 |
| `scale-50000` | `get` | 100 | 14.258 | 29.886 | 1.954 | 887.000 | 100 |
| `scale-50000` | `context/mainline` | 100 | 38.988 | 59.904 | 4.183 | 21679.000 | 100 |
| `scale-50000` | `context/full` | 100 | 57.194 | 77.053 | 7.906 | 241333.000 | 100 |
| `scale-2000` | `sync/initial` | 3 | 412.144 | 456.471 | 6.743 | 524.000 | 3 |
| `scale-2000` | `sync/noop` | 3 | 37.424 | 40.095 | 2.671 | 516.000 | 3 |
| `scale-2000` | `sync/shrink` | 3 | 365.194 | 394.455 | 29.261 | 524.000 | 3 |
| `scale-2000` | `search/token` | 100 | 73.719 | 101.736 | 8.384 | 10522.000 | 100 |
| `scale-2000` | `search/latin` | 100 | 67.040 | 102.516 | 7.305 | 10303.000 | 100 |
| `scale-2000` | `search/cjk` | 100 | 64.109 | 88.990 | 6.635 | 10343.000 | 100 |
| `scale-2000` | `search/path` | 100 | 63.065 | 92.888 | 5.560 | 9943.000 | 100 |
| `scale-2000` | `search/identifier` | 100 | 65.990 | 89.666 | 8.597 | 10503.000 | 100 |
| `scale-2000` | `show` | 100 | 14.414 | 39.247 | 2.204 | 924.000 | 100 |
| `scale-2000` | `get` | 100 | 14.744 | 28.242 | 1.584 | 976.000 | 100 |
| `scale-2000` | `context/mainline` | 100 | 18.307 | 36.713 | 1.359 | 21678.000 | 100 |
| `scale-2000` | `context/full` | 100 | 32.276 | 57.689 | 2.363 | 241333.000 | 100 |
| `scale-10000` | `sync/initial` | 3 | 1687.886 | 1869.047 | 32.645 | 528.000 | 3 |
| `scale-10000` | `sync/noop` | 3 | 32.598 | 35.215 | 2.617 | 518.000 | 3 |
| `scale-10000` | `sync/shrink` | 3 | 1560.987 | 1651.249 | 22.392 | 525.000 | 3 |
| `scale-10000` | `search/token` | 100 | 151.703 | 201.356 | 19.562 | 10507.000 | 100 |
| `scale-10000` | `search/latin` | 100 | 115.002 | 157.097 | 13.335 | 10301.000 | 100 |
| `scale-10000` | `search/cjk` | 100 | 102.161 | 141.895 | 15.073 | 10343.000 | 100 |
| `scale-10000` | `search/path` | 100 | 99.869 | 141.839 | 14.070 | 9943.000 | 100 |
| `scale-10000` | `search/identifier` | 100 | 95.262 | 144.974 | 15.531 | 10503.000 | 100 |
| `scale-10000` | `show` | 100 | 13.024 | 20.190 | 0.748 | 839.000 | 100 |
| `scale-10000` | `get` | 100 | 13.867 | 30.397 | 1.279 | 887.000 | 100 |
| `scale-10000` | `context/mainline` | 100 | 27.976 | 48.618 | 2.641 | 21679.000 | 100 |
| `scale-10000` | `context/full` | 100 | 36.905 | 60.013 | 2.982 | 241333.000 | 100 |

### Corpus and initial-sync throughput

| Workload | Initial Messages | Query Messages | Shrink Messages | Median Messages/s | Median MiB/s |
|---|---:|---:|---:|---:|---:|
| `anchor` | 4000 | 2000 | 2000 | 5562.612 | 1.488 |
| `scale-50000` | 50000 | 50000 | 25000 | 4727.173 | 1.265 |
| `scale-2000` | 2000 | 2000 | 1000 | 4852.669 | 1.298 |
| `scale-10000` | 10000 | 10000 | 5000 | 5924.570 | 1.585 |

### Baseline limitations

- Synthetic positive first-page queries are not recall certification.
- show/get are single-entity reads; context uses one generator-selected Session per scale.
- Twenty startup and three sync samples have limited tail resolution.
- Periodic process RSS is an approximate observation; absent observations remain null.
- CLI duration is an integer-ms pre-render observation, not pure engine time.
- Source SHA-256 is independently recomputed; native fingerprint alignment is checked across scan, document and evidence.
- Boundary resource checks are guardrails, not OS quotas; process creation is not preemptible.
- Build-derived SQLite evidence is not a CLI runtime version query or independent binary attestation.
