# Core/Beta benchmark evidence

- Evidence status: `locally_verified`
- Profile: `full`
- Commit: `88d86f44a0f8d4d0261aaddddb99524514e57d7b`
- OS/target: `windows` / `x86_64-pc-windows-msvc`
- SQLite runtime: `3.53.2` (same-commit sqlite-snapshot-wal rusqlite::version(); workspace and spike lock rusqlite 0.40.1/libsqlite3-sys 0.38.1)
- Dataset: 4000 synthetic messages, SHA-256 `8ebb21d29ce589b9a36b94819a6b4baf2cf0f6c45bf591d552e8d40967833b4e`
- Binary SHA-256: `1afafcee71e5ae15cdad4b6aa382e5868faad71d1bffec641bf4207e490d1119`
- Binary provenance: `built_by_harness_from_workspace`

These results are local evidence anchors, not formal SLOs or release certification.

## Metrics

| Metric | Samples | P50 | P95 | P99 | Mean | Sample stddev |
|---|---:|---:|---:|---:|---:|---:|
| `cli_startup_cold_latency_ms` | 20 | 14.630 | 20.351 | 20.440 | 15.453 | 2.418 |
| `cli_startup_warm_latency_ms` | 20 | 8.444 | 11.709 | 12.988 | 9.028 | 1.701 |
| `initial_sync_latency_ms` | 3 | 1889.167 | 2511.187 | 2511.187 | 2070.311 | 383.827 |
| `noop_sync_latency_ms` | 3 | 1494.681 | 1809.775 | 1809.775 | 1510.335 | 291.928 |
| `shrink_sync_latency_ms` | 3 | 4482.404 | 7104.327 | 7104.327 | 5311.624 | 1553.977 |
| `search_latency_ms` | 100 | 17.727 | 22.441 | 25.399 | 18.989 | 9.324 |
| `show_latency_ms` | 100 | 19.033 | 24.210 | 25.637 | 19.460 | 2.342 |
| `get_latency_ms` | 100 | 18.744 | 25.350 | 113.938 | 23.026 | 29.606 |
| `initial_index_throughput_mb_s` | 3 | 0.566 | 0.591 | 0.591 | 0.528 | 0.089 |

## Sizes

- Release artifact: 2406400 bytes
- Synthetic source: 1122164 bytes
- Store after initial sync including sidecars: 5738496 bytes
- Store after shrink including sidecars: 6082560 bytes
- Store/source ratio: 5.113777

## Recovery

- Status: `not_implemented`
- Reason: The production CLI exposes recovery on open but no fault-injection command; a clean doctor open is not recovery evidence.

## Limitations

- These local measurements are evidence anchors, not formal SLOs or release certification.
- Cold startup uses a fresh copy of the release binary per sample; the harness does not flush OS filesystem caches.
- Startup measures process launch through --version completion, not an interactive readiness signal.
- Peak RSS uses the Windows process peak API where available; Linux /proc and macOS ps are sampled every 100 ms, so short-lived peaks may be missed.
- The SQLite runtime version is operator-supplied and its evidence source is recorded separately; Python's sqlite3 version is diagnostic only.
- Storage size includes the database and present SQLite sidecars after commands exit; no explicit checkpoint command is available.
- Recovery duration is unavailable without a production fault-injection entry point and is not inferred from a clean open.
