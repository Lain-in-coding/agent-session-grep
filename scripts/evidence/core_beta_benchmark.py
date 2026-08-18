#!/usr/bin/env python3
"""Repeatable Core/Beta benchmark evidence for the agent-session-grep CLI.

This harness uses only the Python standard library and generates synthetic
Claude Code JSONL fixtures. It never discovers or reads provider data roots.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "agent-session-grep.core-beta-benchmark/v1"
PROFILES = {
    "smoke": {"files": 2, "messages_per_file": 12, "startup": 3, "sync": 1, "query": 5},
    "full": {"files": 20, "messages_per_file": 200, "startup": 20, "sync": 3, "query": 100},
}
QUERIES = ["benchmarktoken", "alpha", "配置", '"src/main.rs"', "EVIDENCE42"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hash(paths: Iterable[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def nearest_rank(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile / 100 * len(ordered)))
    return ordered[rank - 1]


def summarize(values: list[float]) -> dict[str, float | int]:
    if not values:
        raise ValueError("cannot summarize an empty sample set")
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "p50": nearest_rank(values, 50),
        "p95": nearest_rank(values, 95),
        "p99": nearest_rank(values, 99),
        "mean": statistics.fmean(values),
        "sample_stddev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def rounded(value: float) -> float:
    return round(value, 6)


def rounded_summary(values: list[float]) -> dict[str, float | int]:
    return {key: rounded(value) if isinstance(value, float) else value for key, value in summarize(values).items()}


def peak_working_set_bytes(process: subprocess.Popen[bytes]) -> int | None:
    if os.name == "nt":
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        try:
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(
                ctypes.c_void_p(process._handle),  # type: ignore[attr-defined]
                ctypes.byref(counters),
                counters.cb,
            )
        except (AttributeError, OSError):
            return None
        return int(counters.PeakWorkingSetSize) if ok else None

    status = Path(f"/proc/{process.pid}/status")
    if status.exists():
        try:
            for line in status.read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None

    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["ps", "-o", "rss=", "-p", str(process.pid)],
                check=False,
                capture_output=True,
                text=True,
            )
            value = result.stdout.strip()
            return int(value) * 1024 if value else None
        except (OSError, ValueError):
            return None
    return None


def run_process(
    command: list[str], cwd: Path, env: dict[str, str] | None = None
) -> dict[str, Any]:
    started = time.perf_counter_ns()
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    peaks: list[int] = []
    stop_sampling = threading.Event()

    def sample() -> None:
        while not stop_sampling.is_set():
            value = peak_working_set_bytes(process)
            if value is not None:
                peaks.append(value)
            if process.poll() is not None:
                break
            stop_sampling.wait(0.1)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    stdout, stderr = process.communicate()
    stop_sampling.set()
    sampler.join(timeout=1.0)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if process.returncode != 0:
        raise RuntimeError(
            f"command failed ({process.returncode}): {command!r}\n"
            f"stdout: {stdout.decode('utf-8', errors='replace')}\n"
            f"stderr: {stderr.decode('utf-8', errors='replace')}"
        )
    return {
        "duration_ms": rounded(elapsed_ms),
        "peak_rss_mb": rounded(max(peaks) / (1024 * 1024)) if peaks else None,
        "stdout": stdout.decode("utf-8", errors="strict"),
    }


def parse_frame(output: str) -> dict[str, Any]:
    line = output.splitlines()[0] if output.splitlines() else ""
    frame = json.loads(line)
    if not isinstance(frame, dict) or frame.get("ok") is not True:
        raise RuntimeError(f"CLI did not return a successful Robot frame: {line}")
    return frame


def cli(binary: Path, workspace: Path, db: Path, *args: str) -> dict[str, Any]:
    result = run_process(
        [str(binary), "--db", str(db), "--output", "json", *args], workspace
    )
    result["frame"] = parse_frame(result["stdout"])
    return result


def synthetic_record(index: int, local_index: int) -> dict[str, Any]:
    role = "user" if index % 2 == 0 else "assistant"
    uuid = f"00000000-0000-4000-8000-{index:012d}"
    parent = None if local_index % 10 == 0 else f"00000000-0000-4000-8000-{index - 1:012d}"
    category = ["alpha", "配置", "src/main.rs", "EVIDENCE42"][index % 4]
    return {
        "type": role,
        "uuid": uuid,
        "parentUuid": parent,
        "timestamp": f"2026-01-{(index % 28) + 1:02d}T12:00:00.000Z",
        "isSidechain": index % 17 == 0,
        "message": {
            "role": role,
            "content": f"synthetic benchmarktoken {category} message {index:08d}",
        },
        "synthetic": True,
    }


def write_dataset(root: Path, file_count: int, messages_per_file: int) -> tuple[list[Path], list[str]]:
    root.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    ids: list[str] = []
    index = 0
    for file_number in range(file_count):
        path = root / f"session-{file_number:04d}.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for local_index in range(messages_per_file):
                record = synthetic_record(index, local_index)
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                ids.append(f"msg_v1_{record['uuid']}")
                index += 1
        files.append(path)
    return files, ids


def shrink_dataset(paths: list[Path]) -> None:
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        retained = lines[: max(1, len(lines) // 2)]
        path.write_text("\n".join(retained) + "\n", encoding="utf-8", newline="\n")


def directory_size(paths: Iterable[Path]) -> int:
    return sum(path.stat().st_size for path in paths if path.is_file())


def metric(name: str, unit: str, samples: list[dict[str, Any]], required: int, state: str) -> dict[str, Any]:
    durations = [float(sample["duration_ms"]) for sample in samples]
    peaks = [float(sample["peak_rss_mb"]) for sample in samples if sample["peak_rss_mb"] is not None]
    return {
        "name": name,
        "unit": unit,
        "state": state,
        "required_sample_count": required,
        "raw_samples": durations,
        "summary": rounded_summary(durations),
        "peak_rss_mb_raw_samples": peaks,
        "peak_rss_mb_summary": rounded_summary(peaks) if peaks else None,
    }


def total_memory_bytes() -> int | None:
    if os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        return int(status.ullTotalPhys) if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) else None
    try:
        if sys.platform == "darwin":
            result = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=True)
            return int(result.stdout.strip())
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return int(pages * page_size)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return None


def command_text(command: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def environment(workspace: Path, args: argparse.Namespace) -> dict[str, Any]:
    rustc = command_text([args.rustc, "-vV"], workspace)
    target = None
    if rustc:
        target = next((line.split(":", 1)[1].strip() for line in rustc.splitlines() if line.startswith("host:")), None)
    memory = total_memory_bytes()
    return {
        "captured_at_utc": utc_now(),
        "os": platform.system().lower(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "target_triple": target or "not_recorded",
        "architecture": platform.machine() or "not_recorded",
        "cpu": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER") or "not_recorded",
        "logical_cpu_count": os.cpu_count(),
        "ram_gb": rounded(memory / (1024**3)) if memory else "not_recorded",
        "disk": args.disk,
        "filesystem": args.filesystem,
        "antivirus_state": args.antivirus_state,
        "sqlite_version": args.sqlite_version,
        "sqlite_version_source": args.sqlite_version_source,
        "rustc": rustc or "not_recorded",
        "python_version": platform.python_version(),
        "python_sqlite_version_not_store_version": sqlite3.sqlite_version,
    }


def resolve_binary(workspace: Path, args: argparse.Namespace) -> Path:
    if args.binary:
        binary = Path(args.binary).expanduser().resolve()
    else:
        subprocess.run(
            [args.cargo, "build", "--locked", "--release", "-p", "agent-session-grep-cli"],
            cwd=workspace,
            check=True,
        )
        name = "agent-session-grep.exe" if os.name == "nt" else "agent-session-grep"
        binary = workspace / "target" / "release" / name
    if not binary.is_file():
        raise FileNotFoundError(f"release CLI binary not found: {binary}")
    return binary


def startup_samples(binary: Path, workspace: Path, count: int, scratch: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    for _ in range(3):
        run_process([str(binary), "--version"], workspace)
    warm = [run_process([str(binary), "--version"], workspace) for _ in range(count)]
    cold: list[dict[str, Any]] = []
    for index in range(count):
        suffix = binary.suffix
        copy = scratch / f"startup-cold-{index:03d}{suffix}"
        shutil.copy2(binary, copy)
        cold.append(run_process([str(copy), "--version"], workspace))
        copy.unlink()
    return cold, warm


def run_benchmark(args: argparse.Namespace) -> Path:
    workspace = Path(args.workspace).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    profile = PROFILES[args.profile]
    commit = command_text(["git", "rev-parse", "HEAD"], workspace) or "not_recorded"
    if args.expected_commit and commit != args.expected_commit:
        raise ValueError(
            f"workspace commit {commit!r} does not match --expected-commit {args.expected_commit!r}"
        )
    if args.profile == "full":
        if not args.expected_commit:
            raise ValueError("full evidence requires --expected-commit")
        required_metadata = {
            "disk": args.disk,
            "filesystem": args.filesystem,
            "antivirus_state": args.antivirus_state,
            "sqlite_version": args.sqlite_version,
            "sqlite_version_source": args.sqlite_version_source,
        }
        missing = [
            name
            for name, value in required_metadata.items()
            if value in {"not_recorded", "not_exposed_by_cli"}
        ]
        if missing:
            raise ValueError(f"full evidence requires recorded metadata: {', '.join(missing)}")
    binary = resolve_binary(workspace, args)
    binary_provenance = "caller_supplied_prebuilt" if args.binary else "built_by_harness_from_workspace"

    with tempfile.TemporaryDirectory(prefix="agent-session-grep-evidence-") as temp_name:
        scratch = Path(temp_name)
        master = scratch / "dataset-master"
        dataset_files, all_ids = write_dataset(master, profile["files"], profile["messages_per_file"])
        dataset_bytes = directory_size(dataset_files)
        dataset_digest = tree_hash(dataset_files, master)
        cold, warm = startup_samples(binary, workspace, profile["startup"], scratch)

        initial_samples: list[dict[str, Any]] = []
        noop_samples: list[dict[str, Any]] = []
        shrink_samples: list[dict[str, Any]] = []
        initial_store_bytes_samples: list[int] = []
        initial_store_files: list[str] = []
        final_db: Path | None = None
        final_trial: Path | None = None
        for trial_number in range(profile["sync"]):
            trial = scratch / f"sync-trial-{trial_number:03d}"
            shutil.copytree(master, trial / "dataset")
            paths = sorted((trial / "dataset").glob("*.jsonl"))
            db = trial / "catalog.db"
            initial_samples.append(cli(binary, workspace, db, "sync", *(str(path) for path in paths)))
            initial_files = list(trial.glob("catalog.db*"))
            initial_store_bytes_samples.append(directory_size(initial_files))
            initial_store_files = sorted(path.name for path in initial_files)
            noop_samples.append(cli(binary, workspace, db, "sync", *(str(path) for path in paths)))
            shrink_dataset(paths)
            shrink_samples.append(cli(binary, workspace, db, "sync", *(str(path) for path in paths)))
            final_db, final_trial = db, trial

        if final_db is None or final_trial is None:
            raise RuntimeError("profile must request at least one sync sample")

        query_count = profile["query"]
        search_samples = [cli(binary, workspace, final_db, "search", QUERIES[index % len(QUERIES)]) for index in range(query_count)]
        for index, sample in enumerate(search_samples):
            if not sample["frame"]["data"].get("hits"):
                raise RuntimeError(f"search query returned no synthetic hit: {QUERIES[index % len(QUERIES)]}")
        retained_ids = [all_ids[file_index * profile["messages_per_file"] + local_index]
                        for file_index in range(profile["files"])
                        for local_index in range(max(1, profile["messages_per_file"] // 2))]
        show_samples = [cli(binary, workspace, final_db, "show", retained_ids[index % len(retained_ids)]) for index in range(query_count)]
        get_samples = [cli(binary, workspace, final_db, "get", retained_ids[index % len(retained_ids)]) for index in range(query_count)]
        doctor = cli(binary, workspace, final_db, "doctor")

        initial_durations = [float(item["duration_ms"]) for item in initial_samples]
        throughput = [rounded(dataset_bytes / (1024 * 1024) / (duration / 1000)) if duration > 0 else 0.0 for duration in initial_durations]
        storage_files = list(final_trial.glob("catalog.db*"))
        post_shrink_storage_bytes = directory_size(storage_files)
        initial_store_bytes = initial_store_bytes_samples[-1]
        metrics = {
            "cli_startup_cold_latency_ms": metric("cli_startup_cold_latency_ms", "ms", cold, profile["startup"], "cold_best_effort"),
            "cli_startup_warm_latency_ms": metric("cli_startup_warm_latency_ms", "ms", warm, profile["startup"], "warm"),
            "initial_sync_latency_ms": metric("initial_sync_latency_ms", "ms", initial_samples, profile["sync"], "fresh_store"),
            "noop_sync_latency_ms": metric("noop_sync_latency_ms", "ms", noop_samples, profile["sync"], "warm_unchanged_source"),
            "shrink_sync_latency_ms": metric("shrink_sync_latency_ms", "ms", shrink_samples, profile["sync"], "source_replacement_half_removed"),
            "search_latency_ms": metric("search_latency_ms", "ms", search_samples, query_count, "warm"),
            "show_latency_ms": metric("show_latency_ms", "ms", show_samples, query_count, "warm"),
            "get_latency_ms": metric("get_latency_ms", "ms", get_samples, query_count, "warm"),
            "initial_index_throughput_mb_s": {
                "name": "initial_index_throughput_mb_s", "unit": "MiB/s", "state": "fresh_store",
                "required_sample_count": profile["sync"], "raw_samples": throughput,
                "summary": rounded_summary(throughput), "peak_rss_mb_raw_samples": [], "peak_rss_mb_summary": None,
            },
        }
        peak_values = [value for entry in metrics.values() for value in entry["peak_rss_mb_raw_samples"]]
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "evidence_status": "locally_verified",
            "profile": args.profile,
            "generated_at_utc": utc_now(),
            "commit": commit,
            "environment": environment(workspace, args),
            "dataset": {
                "kind": "deterministic_synthetic_claude_code_jsonl",
                "contains_real_transcripts": False,
                "hash_algorithm": "sha256",
                "dataset_hash": dataset_digest,
                "file_count": profile["files"],
                "message_count": profile["files"] * profile["messages_per_file"],
                "source_bytes": dataset_bytes,
                "query_set": QUERIES,
            },
            "binary": {
                "hash_algorithm": "sha256",
                "binary_hash": sha256_file(binary),
                "artifact_size_bytes": binary.stat().st_size,
                "provenance": binary_provenance,
            },
            "methodology": {
                "clock": "time.perf_counter_ns",
                "percentiles": "nearest-rank",
                "dispersion": "sample standard deviation (n-1); 0 for one sample",
                "warmup": "three --version invocations before warm startup sampling; sync/query measurements use explicit fresh or populated stores",
                "peak_rss_sampling_interval_ms": 100,
                "raw_samples_authoritative": True,
            },
            "metrics": metrics,
            "aggregate_peak_rss_mb": {
                "raw_samples": peak_values,
                "summary": rounded_summary(peak_values) if peak_values else None,
            },
            "sizes": {
                "artifact_size_bytes": binary.stat().st_size,
                "dataset_source_bytes": dataset_bytes,
                "initial_store_bytes_including_sidecars": initial_store_bytes,
                "post_shrink_store_bytes_including_sidecars": post_shrink_storage_bytes,
                "index_size_ratio": rounded(initial_store_bytes / dataset_bytes) if dataset_bytes else None,
                "checkpoint": "not_available_cli_sidecars_measured_after_process_exit",
                "initial_store_bytes_raw_samples": initial_store_bytes_samples,
                "initial_store_files": initial_store_files,
                "post_shrink_store_files": sorted(path.name for path in storage_files),
            },
            "recovery": {
                "status": "not_implemented",
                "recovery_time_ms": None,
                "observation": {
                    "doctor_open_duration_ms": doctor["duration_ms"],
                    "active_generation": doctor["frame"]["data"].get("generation"),
                    "interrupted_batches": doctor["frame"]["data"].get("interrupted_batches"),
                },
                "reason": "The production CLI exposes recovery on open but no fault-injection command; a clean doctor open is not recovery evidence.",
            },
            "limitations": [
                "These local measurements are evidence anchors, not formal SLOs or release certification.",
                "Cold startup uses a fresh copy of the release binary per sample; the harness does not flush OS filesystem caches.",
                "Startup measures process launch through --version completion, not an interactive readiness signal.",
                "Peak RSS uses the Windows process peak API where available; Linux /proc and macOS ps are sampled every 100 ms, so short-lived peaks may be missed.",
                "The SQLite runtime version is operator-supplied and its evidence source is recorded separately; Python's sqlite3 version is diagnostic only.",
                "Storage size includes the database and present SQLite sidecars after commands exit; no explicit checkpoint command is available.",
                "Recovery duration is unavailable without a production fault-injection entry point and is not inferred from a clean open.",
            ],
        }
        if args.binary:
            report["limitations"].append(
                "The measured binary was caller-supplied; its hash is authoritative, but source-to-binary linkage is not independently attested."
            )

    report_path = output_dir / f"core-beta-benchmark-{args.profile}.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    validate_report(report_path, args.profile)
    markdown_path = report_path.with_suffix(".md")
    markdown_path.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    print(report_path)
    return report_path


def assert_summary(samples: list[float], actual: dict[str, Any], label: str) -> None:
    expected = rounded_summary(samples)
    for key, value in expected.items():
        if actual.get(key) != value:
            raise ValueError(f"{label}.summary.{key}: expected {value!r}, got {actual.get(key)!r}")


def validate_report(path: Path, expected_profile: str | None = None) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {report.get('schema_version')!r}")
    if report.get("evidence_status") != "locally_verified":
        raise ValueError("evidence_status must be locally_verified")
    profile_name = report.get("profile")
    if profile_name not in PROFILES or (expected_profile and profile_name != expected_profile):
        raise ValueError(f"unexpected profile: {profile_name!r}")
    commit = report.get("commit", "")
    if not isinstance(commit, str) or len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise ValueError("commit must be a full lowercase Git SHA")
    if report.get("dataset", {}).get("contains_real_transcripts") is not False:
        raise ValueError("dataset.contains_real_transcripts must be false")
    for group, field in (("dataset", "dataset_hash"), ("binary", "binary_hash")):
        value = report.get(group, {}).get(field, "")
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"{group}.{field} must be a lowercase SHA-256 digest")
    provenance = report.get("binary", {}).get("provenance")
    if provenance not in {"built_by_harness_from_workspace", "caller_supplied_prebuilt"}:
        raise ValueError("binary.provenance is not recognized")
    metrics = report.get("metrics")
    if not isinstance(metrics, dict) or not metrics:
        raise ValueError("metrics must be a non-empty object")
    profile = PROFILES[profile_name]
    expected_counts = {
        "cli_startup_cold_latency_ms": profile["startup"],
        "cli_startup_warm_latency_ms": profile["startup"],
        "initial_sync_latency_ms": profile["sync"],
        "noop_sync_latency_ms": profile["sync"],
        "shrink_sync_latency_ms": profile["sync"],
        "initial_index_throughput_mb_s": profile["sync"],
        "search_latency_ms": profile["query"],
        "show_latency_ms": profile["query"],
        "get_latency_ms": profile["query"],
    }
    if set(metrics) != set(expected_counts):
        raise ValueError("metrics do not match the benchmark schema")
    for name, entry in metrics.items():
        samples = entry.get("raw_samples")
        required = entry.get("required_sample_count")
        expected = expected_counts[name]
        if required != expected:
            raise ValueError(f"{name}: required_sample_count must be {expected}, got {required!r}")
        if not isinstance(samples, list) or not samples or len(samples) < expected:
            raise ValueError(f"{name}: insufficient raw samples ({len(samples) if isinstance(samples, list) else 'invalid'} < {expected})")
        if not all(isinstance(value, (int, float)) and value >= 0 for value in samples):
            raise ValueError(f"{name}: samples must be non-negative numbers")
        assert_summary([float(value) for value in samples], entry.get("summary", {}), name)
        peak_samples = entry.get("peak_rss_mb_raw_samples")
        if not isinstance(peak_samples, list) or not all(
            isinstance(value, (int, float)) and value >= 0 for value in peak_samples
        ):
            raise ValueError(f"{name}: peak RSS samples must be a list of non-negative numbers")
        peak_summary = entry.get("peak_rss_mb_summary")
        if peak_samples:
            assert_summary(
                [float(value) for value in peak_samples],
                peak_summary if isinstance(peak_summary, dict) else {},
                f"{name}.peak_rss_mb",
            )
        elif peak_summary is not None:
            raise ValueError(f"{name}: empty peak RSS samples require a null summary")
    aggregate_peak = report.get("aggregate_peak_rss_mb", {})
    expected_peak_samples = [
        value
        for entry in metrics.values()
        for value in entry["peak_rss_mb_raw_samples"]
    ]
    if aggregate_peak.get("raw_samples") != expected_peak_samples:
        raise ValueError("aggregate_peak_rss_mb.raw_samples does not match metric peak samples")
    aggregate_summary = aggregate_peak.get("summary")
    if expected_peak_samples:
        assert_summary(
            [float(value) for value in expected_peak_samples],
            aggregate_summary if isinstance(aggregate_summary, dict) else {},
            "aggregate_peak_rss_mb",
        )
    elif aggregate_summary is not None:
        raise ValueError("empty aggregate peak RSS samples require a null summary")
    sizes = report.get("sizes", {})
    size_fields = ["artifact_size_bytes", "dataset_source_bytes", "initial_store_bytes_including_sidecars", "post_shrink_store_bytes_including_sidecars"]
    if any(not isinstance(sizes.get(field), int) or sizes[field] < 0 for field in size_fields):
        raise ValueError("size fields must be non-negative integers")
    if sizes["artifact_size_bytes"] != report.get("binary", {}).get("artifact_size_bytes"):
        raise ValueError("binary and size artifact byte counts differ")
    dataset = report.get("dataset", {})
    if dataset.get("file_count") != profile["files"]:
        raise ValueError("dataset.file_count does not match the profile")
    if dataset.get("message_count") != profile["files"] * profile["messages_per_file"]:
        raise ValueError("dataset.message_count does not match the profile")
    if sizes["dataset_source_bytes"] != dataset.get("source_bytes"):
        raise ValueError("dataset source byte counts differ")
    initial_size_samples = sizes.get("initial_store_bytes_raw_samples")
    if (
        not isinstance(initial_size_samples, list)
        or len(initial_size_samples) < profile["sync"]
        or not all(isinstance(value, int) and value >= 0 for value in initial_size_samples)
    ):
        raise ValueError("initial_store_bytes_raw_samples does not satisfy the profile")
    recovery = report.get("recovery", {})
    if recovery.get("status") not in {"locally_verified", "not_implemented", "externally_blocked"}:
        raise ValueError("recovery.status is not a recognized evidence status")
    if recovery.get("status") != "locally_verified" and recovery.get("recovery_time_ms") is not None:
        raise ValueError("unverified recovery must not carry a recovery_time_ms result")
    required_environment = [
        "os", "target_triple", "cpu", "ram_gb", "disk", "filesystem",
        "antivirus_state", "sqlite_version", "sqlite_version_source", "rustc",
    ]
    environment_data = report.get("environment", {})
    missing = [field for field in required_environment if field not in environment_data]
    if missing:
        raise ValueError(f"missing environment fields: {', '.join(missing)}")
    if profile_name == "full":
        placeholders = [
            field
            for field in ("disk", "filesystem", "antivirus_state", "sqlite_version", "sqlite_version_source")
            if environment_data.get(field) in {"not_recorded", "not_exposed_by_cli"}
        ]
        if placeholders:
            raise ValueError(f"full report has unrecorded environment fields: {', '.join(placeholders)}")
    limitations = report.get("limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        raise ValueError("limitations must be a list of strings")
    if provenance == "caller_supplied_prebuilt" and not any(
        "source-to-binary linkage" in item for item in limitations
    ):
        raise ValueError("caller-supplied binary reports must disclose unattested source linkage")
    print(f"valid {SCHEMA_VERSION} report: {path}")
    return report


def render_markdown(report: dict[str, Any]) -> str:
    env = report["environment"]
    def display(value: object) -> str:
        return f"{value:.3f}" if isinstance(value, (int, float)) else str(value)

    lines = [
        "# Core/Beta benchmark evidence",
        "",
        f"- Evidence status: `{report['evidence_status']}`",
        f"- Profile: `{report['profile']}`",
        f"- Commit: `{report['commit']}`",
        f"- OS/target: `{env['os']}` / `{env['target_triple']}`",
        f"- SQLite runtime: `{env['sqlite_version']}` ({env['sqlite_version_source']})",
        f"- Dataset: {report['dataset']['message_count']} synthetic messages, SHA-256 `{report['dataset']['dataset_hash']}`",
        f"- Binary SHA-256: `{report['binary']['binary_hash']}`",
        f"- Binary provenance: `{report['binary']['provenance']}`",
        "",
        "These results are local evidence anchors, not formal SLOs or release certification.",
        "",
        "## Metrics",
        "",
        "| Metric | Samples | P50 | P95 | P99 | Mean | Sample stddev |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, entry in report["metrics"].items():
        summary = entry["summary"]
        lines.append(
            f"| `{name}` | {summary['count']} | {display(summary['p50'])} | {display(summary['p95'])} | "
            f"{display(summary['p99'])} | {display(summary['mean'])} | {display(summary['sample_stddev'])} |"
        )
    lines.extend([
        "", "## Sizes", "",
        f"- Release artifact: {report['sizes']['artifact_size_bytes']} bytes",
        f"- Synthetic source: {report['sizes']['dataset_source_bytes']} bytes",
        f"- Store after initial sync including sidecars: {report['sizes']['initial_store_bytes_including_sidecars']} bytes",
        f"- Store after shrink including sidecars: {report['sizes']['post_shrink_store_bytes_including_sidecars']} bytes",
        f"- Store/source ratio: {report['sizes']['index_size_ratio']}",
        "", "## Recovery", "",
        f"- Status: `{report['recovery']['status']}`",
        f"- Reason: {report['recovery']['reason']}",
        "", "## Limitations", "",
    ])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[2]
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="generate fixtures, execute measurements, and emit JSON/Markdown")
    run.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    run.add_argument("--workspace", default=str(root))
    run.add_argument("--output-dir", required=True)
    run.add_argument("--binary", help="explicit prebuilt release CLI; otherwise cargo build --release is run")
    run.add_argument("--cargo", default="cargo")
    run.add_argument("--rustc", default="rustc")
    run.add_argument("--expected-commit", help="full Git SHA required for full evidence; run fails if HEAD differs")
    run.add_argument("--disk", default="not_recorded", help="disk media/model for the evidence environment")
    run.add_argument("--filesystem", default="not_recorded", help="filesystem containing the temporary benchmark data")
    run.add_argument("--antivirus-state", default="not_recorded", help="security software state during the run")
    run.add_argument("--sqlite-version", default="not_recorded", help="SQLite runtime linked into the measured CLI")
    run.add_argument("--sqlite-version-source", default="not_recorded", help="how the linked SQLite runtime version was established")
    validate = sub.add_parser("validate-report", help="validate hashes, fields, counts, and recomputed statistics")
    validate.add_argument("report")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "run":
            run_benchmark(args)
        else:
            validate_report(Path(args.report).expanduser().resolve())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
