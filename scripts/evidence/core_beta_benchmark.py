#!/usr/bin/env python3
"""Repeatable Core/Beta benchmark evidence for the agent-session-grep CLI.

This harness uses only the Python standard library and generates synthetic
Claude Code JSONL fixtures. It never discovers or reads provider data roots.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import math
import os
import platform
import re
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from contextlib import closing, nullcontext
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA_VERSION = "agent-session-grep.core-beta-benchmark/v1"
PROFILES = {
    "smoke": {"files": 2, "messages_per_file": 12, "startup": 3, "sync": 1, "query": 5},
    "full": {"files": 20, "messages_per_file": 200, "startup": 20, "sync": 3, "query": 100},
}
QUERIES = ["benchmarktoken", "alpha", "配置", '"src/main.rs"', "EVIDENCE42"]
BASELINE_SCHEMA = "agent-session-grep.current-source-baseline/v1"
BUILD_SCHEMA = "agent-session-grep.baseline-build/v1"
ATTEMPT_SCHEMA = "agent-session-grep.baseline-attempt/v1"
WALL_PROTOCOL = "process-wall-before-observer/v1"
LEGACY_PROTOCOL = "legacy-wall-with-observer/v1"
SCALES = (("scale-2000", 10), ("scale-10000", 50), ("scale-50000", 250))
QUERY_CLASSES = ("token", "latin", "cjk", "path", "identifier")
HARNESS_PATH = "scripts/evidence/core_beta_benchmark.py"
SUITE_SECONDS = 3600
CHILD_SECONDS = 300
SCRATCH_LIMIT = 4 * 1024**3
SCRATCH_FREE = 8 * 1024**3
RSS_LIMIT_MIB = 4096
SEARCH_OPTIONS = ("--mode", "lexical", "--max-items", "20", "--max-bytes", "4194304")
CONTEXT_OPTIONS = ("--level", "raw", "--max-messages", "500", "--max-bytes", "4194304")
CHILD_POLICY = {
    "trace": "disabled",
    "repository": "derived_from_source_root",
    "application_clock": "system",
    "cwd": "source-root",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hash(paths: Iterable[Path], root: Path) -> str:
    return tree_bytes_hash((path.relative_to(root).as_posix(), path.read_bytes()) for path in paths)


def tree_bytes_hash(entries: Iterable[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for relative, content in sorted(entries):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
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


def memory_method() -> str:
    if os.name == "nt":
        return "windows_peak_working_set"
    return "macos_ps_rss" if sys.platform == "darwin" else "proc_status_rss"


def process_lifecycle(
    command: list[str], cwd: Path, env: dict[str, str] | None = None,
    *, timeout: float | None = None, detailed: bool = False,
) -> dict[str, Any]:
    """One launch and observer for both clocks; callers own protocol checks.

    communicate's timeout does not kill a child. Kill and boundedly drain it
    here, retaining the failed observation. Process creation itself cannot be
    preempted by Python; its elapsed time consumes the same timeout budget.
    """
    started_utc = utc_now() if detailed else None
    started = time.perf_counter_ns()
    peaks: list[int] = []
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
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
    timed_out = False
    cleanup_incomplete = False
    try:
        if timeout is None:
            stdout, stderr = process.communicate()
        else:
            remaining = max(0.0, timeout - (time.perf_counter_ns() - started) / 1e9)
            stdout, stderr = process.communicate(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        process.kill()
        try:
            stdout, stderr = process.communicate(timeout=5.0)
        except subprocess.TimeoutExpired as drain_error:
            stdout = drain_error.output or error.output or b""
            stderr = drain_error.stderr or error.stderr or b""
            cleanup_incomplete = True
            # Windows communicate reader threads may hold buffered pipe locks
            # while a descendant still owns a writer. Closing those buffered
            # objects here can block indefinitely. Retain partial bytes and
            # bound the killed leader's wait; this failed attempt ends the run.
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                cleanup_incomplete = True
    finally:
        stopped = time.perf_counter_ns()
        stopped_utc = utc_now() if detailed else None
        stop_sampling.set()
        sampler.join(timeout=1.0)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return {
        "duration_ms": rounded(elapsed_ms),
        "process_wall_ms": rounded((stopped - started) / 1_000_000),
        "peak_rss_mb": rounded(max(peaks) / (1024 * 1024)) if peaks else None,
        "memory_observations": len(peaks),
        "started_at_utc": started_utc,
        "completed_at_utc": stopped_utc,
        "returncode": process.returncode,
        "timed_out": timed_out,
        "cleanup_incomplete": cleanup_incomplete,
        "stdout_bytes": stdout,
        "stderr_bytes": stderr,
    }


def run_process(
    command: list[str], cwd: Path, env: dict[str, str] | None = None
) -> dict[str, Any]:
    # Keep the imported gate/semantic helper's three keys, inherited environment,
    # unbounded default and observer-inclusive duration exactly as before.
    result = process_lifecycle(command, cwd, env)
    stdout, stderr = result["stdout_bytes"], result["stderr_bytes"]
    if result["returncode"] != 0:
        raise RuntimeError(
            f"command failed ({result['returncode']}): {command!r}\n"
            f"stdout: {stdout.decode('utf-8', errors='replace')}\n"
            f"stderr: {stderr.decode('utf-8', errors='replace')}"
        )
    return {
        "duration_ms": result["duration_ms"],
        "peak_rss_mb": result["peak_rss_mb"],
        "stdout": stdout.decode("utf-8", errors="strict"),
    }


def parse_frame(output: str) -> dict[str, Any]:
    # 按 "\n" 切，不用 str.splitlines()：后者还在 U+2028/U+2029/U+0085 等
    # Unicode 行边界处断开，而 JSON 允许这些码点未转义地出现在字符串里。
    # 真实 transcript 含这类字符时，splitlines 会把单行 envelope 切成碎片。
    line = output.split("\n")[0] if output else ""
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


def environment(workspace: Path, args: argparse.Namespace, rustc_version: str | None = None) -> dict[str, Any]:
    rustc = rustc_version if rustc_version is not None else command_text([args.rustc, "-vV"], workspace)
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


def require(condition: bool, label: str) -> None:
    if not condition:
        # Labels are internal constants, never untrusted output, paths or argv.
        raise ValueError(f"baseline: {label}")


def closed(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == set(keys), f"invalid {label} fields")
    return value


def finite_number(value: Any, *, integer: bool = False) -> bool:
    if not (type(value) is int if integer else type(value) in (int, float)):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def digest_value(value: Any, length: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def json_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def strict_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_: str) -> None:
        raise ValueError("baseline: non-finite JSON number")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)


def public_values(value: Any) -> None:
    """Reject path-bearing/free-form accidental dumps in the public extension."""
    if isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str) and len(key) <= 120, "invalid public key")
            public_values(key)
            public_values(item)
    elif isinstance(value, list):
        require(len(value) <= 100000, "oversized public array")
        for item in value:
            public_values(item)
    elif isinstance(value, str):
        require(len(value) <= 4096 and "\x00" not in value, "invalid public text")
        require(re.search(r"(?i)(?:[a-z]:[\\/]|\\\\|/(?:users|home|tmp|private)/)", value) is None, "private path in public metadata")
        require(not any(ord(char) < 32 and char != "\n" for char in value), "control character in public metadata")
    elif type(value) in (int, float):
        require(math.isfinite(value), "non-finite public number")
    else:
        require(value is None or type(value) is bool, "invalid public value")


def utc_value(value: Any) -> datetime:
    require(isinstance(value, str) and value.endswith("Z"), "invalid UTC timestamp")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError("baseline: invalid UTC timestamp") from None
    require(result.utcoffset() is not None and result.utcoffset().total_seconds() == 0, "UTC timestamp required")
    return result


def baseline_summary(values: list[float]) -> dict[str, Any]:
    result = rounded_summary(values)
    median = nearest_rank(values, 50)
    result["mad"] = rounded(nearest_rank([abs(value - median) for value in values], 50))
    return result


def median_spread(medians: list[float]) -> dict[str, Any]:
    require(len(medians) == 3 and all(finite_number(value) for value in medians), "invalid run medians")
    denominator = nearest_rank(medians, 50)
    width = max(medians) - min(medians)
    spread = 100 * width / denominator if denominator else (0.0 if width == 0 else None)
    return {
        "run_p50_ms": medians,
        "min_p50_ms": min(medians), "max_p50_ms": max(medians),
        "spread_percent": rounded(spread) if spread is not None else None,
        "noise_warning": spread is None or spread > 15,
        "reason": "zero_median_with_positive_range" if spread is None else None,
    }


def baseline_environment(parent: dict[str, str] | None = None, trace: Path | None = None) -> dict[str, str]:
    result = dict(os.environ if parent is None else parent)
    # Windows environment names are case insensitive, including caller maps.
    for key in list(result):
        if key.upper() in {"ASG_INDEX_TRACE", "ASG_CURRENT_REPO", "ASG_CLOCK_MS"}:
            del result[key]
    if trace is not None:
        result["ASG_INDEX_TRACE"] = str(trace)
    return result


def scale_order(ordinal: int) -> list[str]:
    ids = [name for name, _ in SCALES]
    return ids[ordinal - 1:] + ids[:ordinal - 1]


def retrieval_indices(files: int, messages_per_file: int = 200) -> list[int]:
    return [(index % files) * messages_per_file + index // files for index in range(100)]


def fixture_lines(file_index: int, messages_per_file: int, retained: int) -> list[bytes]:
    return [
        json.dumps(synthetic_record(file_index * messages_per_file + local, local), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        for local in range(retained)
    ]


@lru_cache(maxsize=16)
def corpus_identity(files: int, messages_per_file: int, retained: int) -> dict[str, Any]:
    entries = [(f"session-{index:04d}.jsonl", b"\n".join(fixture_lines(index, messages_per_file, retained)) + b"\n") for index in range(files)]
    return {
        "file_count": files, "messages_per_file": messages_per_file,
        "retained_per_file": retained, "source_occurrences": files * retained,
        "source_bytes": sum(len(content) for _, content in entries),
        "hash_algorithm": "sha256", "tree_hash": tree_bytes_hash(entries),
    }


def fixture_context_order(indices: list[int], messages_per_file: int, policy: str) -> list[int]:
    """Oracle for this fixture only, not an implementation of arbitrary graphs.

    Every Session has one document, unique native Messages and valid UTC dates.
    Full order is timestamp then source ordinal (domain/thread.rs). Mainline
    selects a non-sidechain edged leaf, then follows the generator parent chain,
    including a sidechain ancestor: parent resolution uses *all* placements.
    """
    require(policy in {"mainline", "full"} and bool(indices), "invalid fixture context policy")
    present = set(indices)
    key = lambda index: (index % 28, index % messages_per_file)
    if policy == "full":
        return sorted(indices, key=key)
    candidates = [index for index in indices if index % 17 != 0] or indices
    parents = {index - 1 for index in candidates if index % messages_per_file % 10 != 0}
    leaves = [index for index in candidates if index not in parents]
    edged = [index for index in leaves if index % messages_per_file % 10 != 0]
    current = max(edged or leaves or candidates, key=key)
    branch = [current]
    while current % messages_per_file % 10 != 0 and current - 1 in present:
        current -= 1
        branch.append(current)
    return list(reversed(branch))


def frame_success(frame: Any, command: str) -> dict[str, Any]:
    require(isinstance(frame, dict), "Robot frame must be an object")
    require(frame.get("ok") is True and frame.get("outcome") == "success", "unexpected Robot outcome")
    require(frame.get("command") == command and isinstance(frame.get("data"), dict), "wrong Robot command or data")
    require(frame.get("warnings") == [], "unexpected Robot warning")
    page = frame.get("page")
    require(isinstance(page, dict) and type(page.get("has_more")) is bool, "invalid Robot page")
    require(page["has_more"] == isinstance(page.get("next_cursor"), str), "inconsistent Robot page")
    truncation = frame["data"].get("truncation")
    if truncation is not None:
        require(isinstance(truncation, dict) and truncation.get("truncated") is False and truncation.get("reason") is None, "unexpected truncation")
    return frame["data"]


def sync_check(frame: dict[str, Any], files: int, messages: int, phase: str) -> dict[str, int]:
    data = frame_success(frame, "sync")
    require(phase in {"initial", "noop", "shrink"}, "invalid sync phase")
    expected = {
        "sources": files, "emitted": 0 if phase == "noop" else messages,
        "messages": 0 if phase == "noop" else messages,
        "committed": 0 if phase == "noop" else messages,
        "unchanged": messages if phase == "noop" else 0,
        "retained": 0, "deferred": 0, "skipped": 0, "diagnostics": 0,
        "generation": 2 if phase == "shrink" else 1,
    }
    require(all(type(data.get(key)) is int and data[key] == value for key, value in expected.items()), "incorrect sync accounting or generation")
    return expected


class SyntheticOracle:
    """Untimed, read-only census of owned synthetic stores and their relations."""

    def __init__(self, paths: list[Path], messages_per_file: int = 200):
        self.paths = paths
        self.messages_per_file = messages_per_file
        self.bindings: dict[int, dict[str, Any]] = {}
        self.generation = 0
        self.retained = 0
        self.by_wire: dict[str, int] = {}
        self.query_counts: dict[str, int] = {}

    def scan(self, db: Path, retained: int) -> dict[str, Any]:
        require(db.is_file(), "oracle catalog missing")
        # mode=ro forbids creation/migration; the transaction gives one census.
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            catalog = {wire: strict_json(payload) for wire, payload in connection.execute("SELECT id, payload FROM catalog")}
            placements = list(connection.execute("SELECT placement_id, session_id, document_id, message_id, source_ordinal, is_sidechain, byte_start, byte_end FROM message_placements"))
            edges = list(connection.execute("SELECT child_placement_id, parent_message_id, relation FROM message_edges"))
            claims = list(connection.execute("SELECT source_path, placement_id FROM source_placement_membership"))
            members = list(connection.execute("SELECT source_path, message_id, document_id FROM source_membership"))
            scans = list(connection.execute("SELECT source_path, len_bytes, fingerprint FROM source_scans"))
            relations = list(connection.execute("SELECT source_path FROM source_relation_scans"))
            fts_ids = {row[0] for row in connection.execute("SELECT wire_id FROM fts_ids JOIN fts ON fts.rowid=fts_ids.fts_rowid")}
            fts_count = connection.execute("SELECT COUNT(*) FROM fts").fetchone()[0]
            generation = connection.execute("SELECT active_generation FROM store_metadata WHERE singleton=1").fetchone()
        require(generation is not None, "missing catalog generation")
        require(fts_count == len(fts_ids), "orphan or duplicate FTS rows")
        return self.check_tables(catalog, placements, edges, claims, members, scans, relations, fts_ids, generation[0], retained)

    def check_tables(
        self, catalog: dict[str, Any], placements: list[tuple[Any, ...]],
        edges: list[tuple[Any, ...]], claims: list[tuple[Any, ...]],
        members: list[tuple[Any, ...]], scans: list[tuple[Any, ...]],
        relations: list[tuple[Any, ...]], fts_ids: set[str], generation: int, retained: int,
    ) -> dict[str, Any]:
        files, per_file = len(self.paths), self.messages_per_file
        expected: dict[str, tuple[int, int, int, int, dict[str, Any]]] = {}
        for file_index, path in enumerate(self.paths):
            lines = fixture_lines(file_index, per_file, retained)
            require(path.read_bytes() == b"\n".join(lines) + b"\n", "synthetic source bytes changed")
            offset = 0
            for local, line in enumerate(lines):
                index = file_index * per_file + local
                record = synthetic_record(index, local)
                expected[f"msg_v1_{record['uuid']}"] = (index, file_index, offset, offset + len(line), record)
                offset += len(line) + 1
        require({wire for wire in catalog if wire.startswith("msg_")} == set(expected), "catalog has missing, retained or removed Message identities")
        require(fts_ids == set(expected), "FTS has missing or removed Message identities")
        require(len(placements) == len(expected), "incorrect Placement census")
        by_message = {row[3]: row for row in placements}
        require(set(by_message) == set(expected), "incorrect Placement Message identity")
        self.bindings = {}
        documents: dict[int, str] = {}
        sessions: dict[int, str] = {}
        expected_edges: set[tuple[str, str, str]] = set()
        expected_claims: set[tuple[str, str]] = set()
        expected_members: set[tuple[str, str, str]] = set()
        for wire, (index, file_index, start, end, record) in expected.items():
            placement, session, document, _, ordinal, sidechain, byte_start, byte_end = by_message[wire]
            require(isinstance(placement, str) and placement.startswith("plc_"), "invalid Placement identity")
            require(isinstance(session, str) and session.startswith("ses_v1_") and isinstance(document, str) and document.startswith("doc_v1_"), "invalid contextual identity")
            require((ordinal, sidechain, byte_start, byte_end) == (index % per_file, int(record["isSidechain"]), start, end), "incorrect Placement source facts")
            if file_index in documents:
                require((documents[file_index], sessions[file_index]) == (document, session), "fixture file spans unexpected Sessions or documents")
            documents[file_index], sessions[file_index] = document, session
            source = str(self.paths[file_index].resolve())
            expected_claims.add((source, placement))
            expected_members.add((source, wire, document))
            parent = f"msg_v1_{record['parentUuid']}" if record["parentUuid"] else None
            if parent is not None:
                expected_edges.add((placement, parent, "subagent" if record["isSidechain"] else "reply"))
            entity = catalog[wire]
            self.check_entity(entity, index)
            require(entity.get("session") == session and entity.get("sessions") == [session], "incorrect Message Session membership")
            require(entity.get("parent") == parent and entity.get("is_sidechain") is record["isSidechain"], "incorrect Message parent or sidechain")
            self.bindings[index] = {
                "generator_index": index, "message_id": wire, "placement_id": placement,
                "session_id": session, "source_document_id": document,
                "source_ordinal": ordinal, "byte_start": start, "byte_end": end,
            }
        require(len(set(documents.values())) == files and len(set(sessions.values())) == files, "unexpected fixture Session or document census")
        expected_ids = set(expected) | set(documents.values()) | set(sessions.values())
        require(set(catalog) == expected_ids, "orphan or missing catalog entity")
        scan_map = {str(Path(source).resolve()): (length, fingerprint) for source, length, fingerprint in scans}
        require(len(scans) == files and set(scan_map) == {str(path.resolve()) for path in self.paths}, "unexpected source scan census")
        for file_index, path in enumerate(self.paths):
            document, session = documents[file_index], sessions[file_index]
            payload = catalog[document]
            fingerprint = payload.get("fingerprint")
            require(isinstance(fingerprint, str) and re.fullmatch(r"[A-Za-z0-9:_-]{16,128}", fingerprint) is not None, "invalid observed source fingerprint")
            require(scan_map[str(path.resolve())] == (path.stat().st_size, fingerprint), "source fingerprint or byte census mismatch")
            require(payload.get("len") == path.stat().st_size, "incorrect SourceDocument length")
            expected_wires = [self.bindings[file_index * per_file + local]["message_id"] for local in range(retained)]
            require(catalog[session].get("messages") == expected_wires and catalog[session].get("documents") == [document], "incorrect Session membership")
            for wire in (document, session):
                expected_members.add((str(path.resolve()), wire, document))
            for local in range(retained):
                self.bindings[file_index * per_file + local]["source_fingerprint"] = fingerprint
        normalize = lambda rows: {(str(Path(row[0]).resolve()), *row[1:]) for row in rows}
        require(set(edges) == expected_edges and len(edges) == len(expected_edges), "incorrect fixture parent edges")
        require(normalize(claims) == expected_claims and len(claims) == len(expected_claims), "incorrect source Placement claims")
        require(normalize(members) == expected_members and len(members) == len(expected_members), "incorrect source entity claims")
        require(normalize(relations) == {(str(path.resolve()),) for path in self.paths} and len(relations) == files, "incomplete source relations")
        require(type(generation) is int and generation == (1 if retained == per_file else 2), "incorrect active generation")
        self.generation, self.retained = generation, retained
        self.by_wire = {item["message_id"]: index for index, item in self.bindings.items()}
        self.query_counts = {
            name: sum(query.strip('"') in facts[4]["message"]["content"] for facts in expected.values())
            for name, query in zip(QUERY_CLASSES, QUERIES)
        }
        return {
            "messages": len(expected), "placements": len(placements), "sessions": len(sessions),
            "documents": len(documents), "sources": len(scans), "edges": len(edges),
            "catalog_entities": len(catalog), "fts_messages": len(fts_ids),
            "source_placement_claims": len(claims), "source_entity_claims": len(members),
            "generation": generation, "retained_verified": len(expected),
            "removed_verified": files * (per_file - retained),
            "bindings_sha256": json_hash([self.bindings[index] for index in sorted(self.bindings)]),
        }

    def check_entity(self, entity: Any, index: int) -> None:
        record = synthetic_record(index, index % self.messages_per_file)
        require(isinstance(entity, dict), "missing entity")
        require((entity.get("role"), entity.get("text"), entity.get("timestamp")) == (record["type"], record["message"]["content"], record["timestamp"]), "incorrect entity identity, role or content")

    def check_read(self, frame: dict[str, Any], operation: str, index: int) -> dict[str, Any]:
        data = frame_success(frame, operation)
        require(index in self.bindings, "requested entity outside verified corpus")
        entity = data.get("entity") if operation == "show" else strict_json(data.get("payload", "null"))
        self.check_entity(entity, index)
        require(entity.get("session") == self.bindings[index]["session_id"], "wrong entity Session")
        return {"generator_index": index, "message_id": self.bindings[index]["message_id"]}

    def check_search(self, frame: dict[str, Any], query_class: str) -> dict[str, Any]:
        data = frame_success(frame, "search")
        require(data.get("retrieval_mode") == "lexical" and data.get("generation") == self.generation, "incorrect lexical mode or generation")
        hits = data.get("hits")
        require(isinstance(hits, list) and 0 < len(hits) <= 20, "incorrect first-page hit count")
        token = QUERIES[QUERY_CLASSES.index(query_class)].strip('"')
        by_wire = self.by_wire
        seen: set[str] = set()
        for hit in hits:
            require(isinstance(hit, dict) and hit.get("id") in by_wire and hit["id"] not in seen, "unexpected search identity")
            seen.add(hit["id"])
            index = by_wire[hit["id"]]
            expected = synthetic_record(index, index % self.messages_per_file)["message"]["content"]
            require(token in expected and hit.get("text") == expected, "irrelevant search result")
            require(hit.get("session_id") == self.bindings[index]["session_id"], "incorrect search Session")
        expected_count = self.query_counts[query_class]
        require(len(hits) == min(20, expected_count) and frame["page"]["has_more"] == (expected_count > 20), "incorrect first-page behavior")
        return {"generation": self.generation, "hit_count": len(hits), "result_ids_sha256": json_hash([hit["id"] for hit in hits])}

    def context_anchor(self) -> dict[str, Any]:
        indices = list(range(self.retained))
        require(bool(indices) and len(indices) <= 500, "context fixture exceeds budget")
        binding = self.bindings[0]
        return {
            "generator_file": 0, "session_id": binding["session_id"],
            "source_document_id": binding["source_document_id"],
            "source_fingerprint": binding["source_fingerprint"],
            "source_sha256": sha256_file(self.paths[0]),
            "members": [self.bindings[index] for index in indices],
            "mainline_order": fixture_context_order(indices, self.messages_per_file, "mainline"),
            "full_order": fixture_context_order(indices, self.messages_per_file, "full"),
        }

    def check_context(self, frame: dict[str, Any], policy: str) -> dict[str, Any]:
        data = frame_success(frame, "context")
        expected = fixture_context_order(list(range(self.retained)), self.messages_per_file, policy)
        require(data.get("session_id") == self.bindings[0]["session_id"] and data.get("generation") == self.generation, "incorrect context Session or generation")
        require(data.get("requested_level") == "raw" and data.get("effective_level") == "raw", "incorrect context level")
        session = data.get("session")
        require(isinstance(session, dict) and session.get("messages") == [self.bindings[index]["message_id"] for index in range(self.retained)] and session.get("documents") == [self.bindings[0]["source_document_id"]], "incorrect embedded context Session")
        require(data.get("tool_activities") == [], "unexpected synthetic context activities")
        messages, evidence = data.get("messages"), data.get("evidence")
        require(isinstance(messages, list) and isinstance(evidence, list) and len(messages) == len(evidence) == len(expected), "incorrect context membership")
        for index, message, span in zip(expected, messages, evidence):
            binding = self.bindings[index]
            require(isinstance(message, dict) and isinstance(span, dict), "invalid context message or evidence")
            require(message.get("id") == message.get("message_id") == binding["message_id"] and message.get("placement_id") == binding["placement_id"], "incorrect context order or occurrence")
            self.check_entity(message.get("payload"), index)
            checks = {
                "occurrence_id": binding["placement_id"], "message_id": binding["message_id"],
                "source_document_id": binding["source_document_id"], "source_fingerprint": binding["source_fingerprint"],
                "byte_start": binding["byte_start"], "byte_end": binding["byte_end"],
                "record_ordinal": binding["source_ordinal"], "generation": self.generation,
                "precision": "byte", "line_start": None, "line_end": None,
                "snippet_char_start": None, "snippet_char_end": None,
            }
            require(all(span.get(key) == value for key, value in checks.items()), "incorrect context evidence alignment")
        leaf = self.bindings[expected[-1]]
        require(data.get("branch_leaf") == leaf["message_id"] and data.get("branch_leaf_placement_id") == leaf["placement_id"], "incorrect context leaf")
        return {"generation": self.generation, "message_count": len(expected), "order_sha256": json_hash(expected), "evidence_count": len(evidence)}


def checked_command(command: list[str], workspace: Path, *, env: dict[str, str] | None = None, timeout: float = 60) -> str:
    try:
        result = subprocess.run(command, cwd=workspace, env=env, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("baseline: provenance command unavailable") from None
    require(result.returncode == 0, "provenance command failed")
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError:
        raise ValueError("baseline: invalid provenance command output") from None


def source_identity(workspace: Path, expected: str) -> dict[str, Any]:
    require(digest_value(expected, 40), "expected measured source SHA required")
    require(Path(__file__).resolve() == workspace / HARNESS_PATH, "harness must execute from measured source checkout")
    require(checked_command(["git", "rev-parse", "--show-toplevel"], workspace).replace("\\", "/").casefold() == workspace.as_posix().casefold(), "workspace must be the source root")
    commit = checked_command(["git", "rev-parse", "HEAD"], workspace)
    require(commit == expected, "HEAD differs from expected measured source")
    status = checked_command(["git", "status", "--porcelain=v1", "--untracked-files=all"], workspace)
    require(not status, "tracked, staged or relevant untracked source is dirty")
    remote = checked_command(["git", "remote", "get-url", "origin"], workspace)
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?", remote)
    require(match is not None, "source repository identity is not a public GitHub slug")
    require(match.group(1) == "Lain-in-coding/agent-session-grep", "unexpected source repository")
    # Git blob identity plus clean index/worktree binds the actual checker bytes.
    tracked = checked_command(["git", "ls-files", "--", HARNESS_PATH, "Cargo.lock", "Cargo.toml"], workspace).splitlines()
    require(set(tracked) == {HARNESS_PATH, "Cargo.lock", "Cargo.toml"}, "missing tracked source inputs")
    return {
        "commit": commit, "harness_commit": commit, "checker_commit": commit,
        "harness_path": HARNESS_PATH, "harness_sha256": sha256_file(workspace / HARNESS_PATH),
        "checker_sha256": sha256_file(workspace / HARNESS_PATH),
        "cargo_lock_sha256": sha256_file(workspace / "Cargo.lock"),
        "cargo_manifest_sha256": sha256_file(workspace / "Cargo.toml"),
        "repository": match.group(1),
        "cleanliness": {"tracked": "clean", "index": "clean", "untracked": "clean"},
    }


def build_configuration(workspace: Path, args: argparse.Namespace) -> tuple[dict[str, Any], Path, Path]:
    """Conservative qualified profile: reject unproved compiler/link overrides.

    Cargo configuration is hierarchical. Do not silently ignore a user/ancestor
    config or try to parse arbitrary TOML with a partial Python 3.10 parser.
    CARGO_TARGET_DIR / BUILD_TARGET / BUILD_JOBS are explicitly understood;
    other build-affecting settings require a separate reviewed protocol.
    """
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).expanduser().resolve()
    config_roots = [path / ".cargo" for path in (workspace, *workspace.parents)] + [cargo_home]
    require(not any((root / name).exists() for root in config_roots for name in ("config", "config.toml")), "unsupported Cargo configuration prevents linkage proof")
    allowed = {"CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_BUILD_JOBS", "CARGO_TERM_COLOR", "CARGO_TERM_PROGRESS_WHEN", "CARGO_TERM_PROGRESS_WIDTH"}
    forbidden_names = {"RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN", "CC", "CXX", "AR", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CRATE_CC_NO_DEFAULTS", "CC_ENABLE_DEBUG_OUTPUT"}
    forbidden_names.update(prefix + "_" + variable for prefix in ("HOST", "TARGET") for variable in ("CC", "CXX", "AR", "CFLAGS", "CXXFLAGS", "LDFLAGS"))
    for key, value in os.environ.items():
        upper = key.upper()
        forbidden = upper in forbidden_names or upper.startswith(("LIBSQLITE3", "SQLITE", "SQLCIPHER", "PKG_CONFIG", "CARGO_ENCODED_", "CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_", "RUSTC_", "CC_", "CXX_", "AR_", "CFLAGS_", "CXXFLAGS_"))
        require(upper in allowed or not forbidden, "unsupported build environment override prevents linkage proof")
        require(upper not in {"CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_BUILD_JOBS"} or bool(value), "empty build environment override is unsupported")
    cargo = Path(shutil.which(args.cargo) or args.cargo).expanduser().resolve()
    rustc = Path(shutil.which(args.rustc) or args.rustc).expanduser().resolve()
    require(cargo.is_file() and cargo.stem == "cargo" and rustc.is_file() and rustc.stem == "rustc", "unresolved Cargo or rustc executable")
    require(cargo == Path(shutil.which("cargo") or "").resolve() and rustc == Path(shutil.which("rustc") or "").resolve(), "qualified baseline requires the native Cargo/rustc pair selected by PATH")
    rustc_version = checked_command([str(rustc), "-vV"], workspace)
    host_match = re.search(r"(?m)^host: ([a-z0-9_-]+)$", rustc_version)
    require(host_match is not None, "rustc host target unavailable")
    target = os.environ.get("CARGO_BUILD_TARGET") or host_match.group(1)
    require(target == host_match.group(1), "baseline requires a native target")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", str(workspace / "target"))).expanduser()
    if not target_dir.is_absolute():
        target_dir = workspace / target_dir
    jobs = os.environ.get("CARGO_BUILD_JOBS")
    require(jobs is None or re.fullmatch(r"[1-9][0-9]{0,2}", jobs) is not None, "unsupported build jobs")
    config = {
        "target": target, "rustc": rustc_version,
        "cargo_tool_sha256": sha256_file(cargo), "rustc_tool_sha256": sha256_file(rustc),
        "environment": {
            "CARGO_BUILD_TARGET": os.environ.get("CARGO_BUILD_TARGET"),
            "CARGO_BUILD_JOBS": jobs,
            "CARGO_TARGET_DIR": "explicit-build-target" if os.environ.get("CARGO_TARGET_DIR") else "source-root/target",
        },
        "cargo_configuration": "none", "compiler_link_overrides": "none",
    }
    public_values(config)
    return config, target_dir.resolve(), cargo_home


def locked_sqlite(workspace: Path) -> dict[str, str]:
    # Only three canonical Cargo.lock string scalars, not a general TOML reader.
    candidates = []
    for stanza in re.split(r"(?m)^\[\[package\]\]\s*$", (workspace / "Cargo.lock").read_text(encoding="utf-8"))[1:]:
        fields = {key: value for key, value in re.findall(r'(?m)^(name|version|checksum|source) = "([^"\r\n]+)"\s*$', stanza)}
        if fields.get("name") == "libsqlite3-sys":
            candidates.append(fields)
    require(len(candidates) == 1, "locked libsqlite3-sys package is ambiguous")
    fields = candidates[0]
    require(set(fields) == {"name", "version", "checksum", "source"} and digest_value(fields["checksum"]), "missing locked SQLite archive checksum")
    require(fields["source"] == "registry+https://github.com/rust-lang/crates.io-index", "unsupported SQLite source registry")
    return fields


def sqlite_source_proof(package: dict[str, Any], locked: dict[str, str], cargo_home: Path) -> dict[str, Any]:
    require(package.get("version") == locked["version"] and package.get("source") == locked["source"], "resolved SQLite differs from Cargo.lock")
    manifest = Path(package["manifest_path"])
    source = manifest.parent
    prefix = f"libsqlite3-sys-{locked['version']}"
    require(source.name == prefix and source.parent.parent == cargo_home / "registry" / "src", "unsupported SQLite package layout")
    archive = cargo_home / "registry" / "cache" / source.parent.name / f"{prefix}.crate"
    require(archive.is_file() and sha256_file(archive) == locked["checksum"], "SQLite crate archive is missing or differs from lock")
    contents: dict[str, bytes] = {}
    with tarfile.open(archive, "r:gz") as handle:
        for member in handle:
            require(not member.issym() and not member.islnk(), "unexpected SQLite archive link")
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            require(len(parts) >= 2 and parts[0] == prefix and ".." not in parts, "invalid SQLite archive member")
            relative = Path(*parts[1:])
            stream = handle.extractfile(member)
            require(stream is not None, "SQLite archive member unavailable")
            content = stream.read()
            actual = source / relative
            require(actual.is_file() and not actual.is_symlink() and sha256_file(actual) == hashlib.sha256(content).hexdigest(), "SQLite build source differs from locked archive")
            if relative.as_posix() in {"sqlite3/sqlite3.h", "sqlite3/sqlite3.c", "build.rs"}:
                contents[relative.as_posix()] = content
    require(set(contents) == {"sqlite3/sqlite3.h", "sqlite3/sqlite3.c", "build.rs"}, "missing bundled SQLite source")
    versions = []
    for name in ("sqlite3/sqlite3.h", "sqlite3/sqlite3.c"):
        match = re.search(rb'(?m)^#define SQLITE_VERSION\s+"([0-9.]+)"', contents[name])
        require(match is not None, "bundled SQLite version unavailable")
        versions.append(match.group(1).decode("ascii"))
    require(versions[0] == versions[1], "bundled SQLite versions differ")
    return {
        "package": "libsqlite3-sys", "package_version": locked["version"],
        "archive_sha256": locked["checksum"], "sqlite_version": versions[0],
        "header_sha256": hashlib.sha256(contents["sqlite3/sqlite3.h"]).hexdigest(),
        "source_sha256": hashlib.sha256(contents["sqlite3/sqlite3.c"]).hexdigest(),
        "build_script_sha256": hashlib.sha256(contents["build.rs"]).hexdigest(),
        "method": "locked-bundled-source-and-build-linkage",
        "runtime_query": False,
    }


def bundled_sqlite_library(out_dir: Path, target: str) -> Path:
    # cc creates both names on MSVC: the linker requires sqlite3.lib, while
    # libsqlite3.a is retained as a hard-link or byte-identical copy.
    name = "sqlite3.lib" if target.endswith("-msvc") else "libsqlite3.a"
    native = out_dir / name
    require(native.is_file(), "target-native bundled SQLite library unavailable")
    size, digest = native.stat().st_size, sha256_file(native)
    for alias_name in {"sqlite3.lib", "libsqlite3.a"} - {name}:
        alias = out_dir / alias_name
        if alias.exists() or alias.is_symlink():
            require(alias.is_file() and alias.stat().st_size == size and sha256_file(alias) == digest,
                    "conflicting bundled SQLite library alias")
    return native


def build_receipt(workspace: Path, suite_root: Path, args: argparse.Namespace, source: dict[str, Any], config: dict[str, Any], cargo_home: Path) -> tuple[Path, dict[str, Any]]:
    env = baseline_environment()
    metadata = strict_json(checked_command([args.cargo, "metadata", "--locked", "--format-version", "1"], workspace, env=env, timeout=300))
    packages = metadata.get("packages", [])
    sqlite_packages = [package for package in packages if package.get("name") == "libsqlite3-sys"]
    cli_packages = [package for package in packages if package.get("name") == "agent-session-grep-cli"]
    require(len(sqlite_packages) == len(cli_packages) == 1, "ambiguous build packages")
    sqlite_package, cli_package = sqlite_packages[0], cli_packages[0]
    proof = sqlite_source_proof(sqlite_package, locked_sqlite(workspace), cargo_home)
    # Compiler JSON is the authority for the actual executable, including target
    # directories. Never fall back to a stale target/release pathname.
    command = [args.cargo, "build", "--locked", "--release", "-p", "agent-session-grep-cli", "--message-format=json"]
    output = checked_command(command, workspace, env=env, timeout=3600)
    events = [strict_json(line) for line in output.split("\n") if line.startswith("{")]
    require(any(event.get("reason") == "build-finished" and event.get("success") is True for event in events), "Cargo did not finish successfully")
    artifacts = [event for event in events if event.get("reason") == "compiler-artifact" and event.get("package_id") == cli_package["id"] and event.get("target", {}).get("name") == "agent-session-grep" and event.get("executable")]
    sqlite_artifacts = [event for event in events if event.get("reason") == "compiler-artifact" and event.get("package_id") == sqlite_package["id"] and "lib" in event.get("target", {}).get("kind", [])]
    links = [event for event in events if event.get("reason") == "build-script-executed" and event.get("package_id") == sqlite_package["id"]]
    require(len(artifacts) == len(sqlite_artifacts) == len(links) == 1, "missing exact executable or SQLite build evidence")
    artifact, sqlite_artifact, link = artifacts[0], sqlite_artifacts[0], links[0]
    features = sqlite_artifact.get("features", [])
    require("bundled" in features and not any("sqlcipher" in feature or "loadable_extension" in feature for feature in features), "SQLite did not use the supported bundled feature")
    require(link.get("linked_libs") == ["static=sqlite3"], "SQLite linkage is not exclusively static bundled sqlite3")
    out_dir = Path(link["out_dir"]).resolve()
    require(any(Path(path.removeprefix("native=")).resolve() == out_dir for path in link.get("linked_paths", [])), "SQLite native search path does not match build output")
    library = bundled_sqlite_library(out_dir, config["target"])
    proof.update({
        "features": sorted(features), "linked_libraries": link["linked_libs"],
        "native_library_sha256": sha256_file(library),
        "native_library_size_bytes": library.stat().st_size,
    })
    built = Path(artifact["executable"]).resolve()
    target_directory = Path(metadata["target_directory"]).resolve()
    require(built.is_file() and built.is_relative_to(target_directory) and built.suffix in {"", ".exe"}, "Cargo executable artifact is invalid")
    require(artifact.get("profile", {}).get("opt_level") == "3" and artifact["profile"].get("test") is False and artifact["profile"].get("debug_assertions") is False, "unexpected release profile")
    require(source_identity(workspace, args.expected_commit) == source, "source changed during build")
    destination = suite_root / ("baseline-cli.exe" if os.name == "nt" else "baseline-cli")
    require(not destination.exists(), "frozen binary already exists")
    shutil.copy2(built, destination)
    receipt = {
        "schema_version": BUILD_SCHEMA, "origin_run": 1, "source": source,
        "configuration": config, "cargo_version": checked_command([args.cargo, "--version"], workspace),
        "command": ["cargo", *command[1:]],
        "features": sorted(artifact.get("features", [])), "release_profile": artifact["profile"],
        "artifact_was_cached": artifact.get("fresh"),
        "artifact_relative_to_target": built.relative_to(target_directory).as_posix(),
        "binary_sha256": sha256_file(destination), "binary_size_bytes": destination.stat().st_size,
        "sqlite": proof, "linkage": "harness-build-receipt-not-independent-attestation",
    }
    public_values(receipt)
    require(sha256_file(built) == receipt["binary_sha256"], "binary changed while freezing")
    return destination, receipt


class SuiteBudget:
    def __init__(self, started_ns: int, started_at_utc: str):
        self.started_ns = started_ns
        self.started_at_utc = started_at_utc
        require(type(started_ns) is int and 0 < started_ns <= time.monotonic_ns(), "invalid shared monotonic start")
        utc_value(started_at_utc)

    def elapsed_ms(self) -> float:
        elapsed = (time.monotonic_ns() - self.started_ns) / 1e6
        require(elapsed >= 0, "suite monotonic clock changed")
        return rounded(elapsed)

    def remaining(self) -> float:
        remaining = SUITE_SECONDS - self.elapsed_ms() / 1000
        require(remaining > 0, "shared suite deadline exhausted")
        return remaining

    def boundary(self, scratch: Path, peak_mib: float | None) -> None:
        self.remaining()
        require(peak_mib is None or peak_mib <= RSS_LIMIT_MIB, "observed process RSS exceeds guardrail")
        size = 0
        for root, directories, names in os.walk(scratch, followlinks=False):
            require(not any((Path(root) / name).is_symlink() for name in directories + names), "unexpected link in owned scratch")
            size += sum((Path(root) / name).stat().st_size for name in names)
            require(size <= SCRATCH_LIMIT, "managed scratch exceeds guardrail")


def write_json_new(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")


def replace_owned_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".pending")
    write_json_new(temporary, value)
    os.replace(temporary, path)


def cleanup_scratch(scratch: Path, owner: dict[str, Any]) -> None:
    require(not scratch.is_symlink() and scratch.resolve() == Path(owner["root"]), "scratch root ownership mismatch")
    marker = scratch / ".baseline-owner.json"
    require(marker.is_file() and strict_json(marker.read_text(encoding="utf-8")) == owner, "scratch marker ownership mismatch")
    for root, directories, names in os.walk(scratch, followlinks=False):
        require(not any((Path(root) / name).is_symlink() for name in directories + names), "unexpected link in scratch cleanup")
    shutil.rmtree(scratch)


def launch_size_check(command: list[str], env: dict[str, str]) -> None:
    if os.name == "nt":
        units = len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2 + 1
        require(units <= 32767, "largest sync exceeds Windows command-line limit")
    else:
        budget = os.sysconf("SC_ARG_MAX")
        size = sum(len(os.fsencode(value)) + 1 for value in command)
        size += sum(len(os.fsencode(key + "=" + value)) + 1 for key, value in env.items())
        require(size + 8192 < budget, "largest sync exceeds native launch limit")


def largest_sync_preflight(binary: Path, scratch: Path) -> None:
    paths = [scratch / "scale-50000" / "t3" / "d" / f"session-{index:04d}.jsonl" for index in range(250)]
    launch_size_check([str(binary), "--db", str(scratch / "scale-50000" / "t3" / "catalog.db"), "--output", "json", "sync", *(str(path) for path in paths)], baseline_environment())


def new_section(name: str, files: int, per_file: int = 200) -> dict[str, Any]:
    return {
        "id": name, "file_count": files, "messages_per_file": per_file,
        "query_phase": "post_shrink" if name == "anchor" else "intact",
        "query_trial": 1 if name == "preflight" else 3,
        "snapshots": [], "observations": [], "context_anchor": None,
        "retrieval_indices": list(range(100)) if name == "anchor" else (retrieval_indices(files, per_file) if name != "preflight" else [1]),
        "summaries": {}, "derived": {},
    }


def observation_key(record: dict[str, Any]) -> str:
    name = record["operation"]
    if name == "sync":
        return f"sync/{record['phase']}"
    if name == "search":
        return f"search/{record['query_class']}"
    if name == "context":
        return f"context/{record['policy']}"
    return name


def section_summaries(section: dict[str, Any]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in section["observations"]:
        if record["role"] == "measured":
            require(record["outcome"] == "success" and record["exit_code"] == 0, "failed observation in successful statistics")
            groups.setdefault(observation_key(record), []).append(record)
    result = {}
    for key, records in groups.items():
        peaks = [record["memory"]["peak_rss_mib"] for record in records if record["memory"]["peak_rss_mib"] is not None]
        cli_times = [record["cli_reported_duration_ms"] for record in records if record["cli_reported_duration_ms"] is not None]
        result[key] = {
            "process_wall_ms": baseline_summary([record["process_wall_ms"] for record in records]),
            "stdout_bytes": baseline_summary([record["stdout_bytes"] for record in records]),
            "peak_rss_mib": baseline_summary(peaks) if peaks else None,
            "memory_available_count": len(peaks),
            "cli_reported_duration_ms": baseline_summary(cli_times) if cli_times else None,
            "cli_duration_available_count": len(cli_times),
        }
    return result


def section_derived(section: dict[str, Any]) -> dict[str, Any]:
    snapshots = section["snapshots"]
    measured = [record for record in section["observations"] if record["role"] == "measured" and record["operation"] == "sync" and record["phase"] == "initial"]
    messages, mib = [], []
    for record in measured:
        require(record["process_wall_ms"] > 0, "initial sync requires a positive wall time")
        snapshot = next(item for item in snapshots if item["trial"] == record["trial"] and item["phase"] == "initial")
        seconds = record["process_wall_ms"] / 1000
        messages.append(rounded(snapshot["corpus"]["source_occurrences"] / seconds))
        mib.append(rounded(snapshot["corpus"]["source_bytes"] / 1024**2 / seconds))
    return {
        "initial_messages_per_second": {"raw_samples": messages, "summary": baseline_summary(messages) if messages else None},
        "initial_mib_per_second": {"raw_samples": mib, "summary": baseline_summary(mib) if mib else None},
        "store_source_ratios": [{"phase": item["phase"], "trial": item["trial"], "ratio": rounded(item["store"]["total_bytes"] / item["corpus"]["source_bytes"])} for item in snapshots],
    }


def baseline_plan(ordinal: int) -> dict[str, Any]:
    return {
        "scale_order": scale_order(ordinal),
        "scales": [{"id": name, "file_count": files, "messages_per_file": 200} for name, files in SCALES],
        "query_classes": [{"id": name, "query": query} for name, query in zip(QUERY_CLASSES, QUERIES)],
        "sync_trials": 3, "query_warmups": 3, "query_samples_per_class_or_operation": 100,
        "search_options": list(SEARCH_OPTIONS), "context_options": list(CONTEXT_OPTIONS),
        "context_policies": ["mainline", "full"], "search_order": "round-robin-after-all-class-warmups",
        "retrieval_selection": "file-round-robin-generator-indices/v1", "context_generator_file": 0,
        "timing_protocol": WALL_PROTOCOL, "legacy_timing_protocol": LEGACY_PROTOCOL,
        "memory_method": memory_method(), "memory_interval_ms": 100,
        "stdout_byte_definition": "captured-UTF-8-bytes-including-final-LF",
        "suite_seconds": SUITE_SECONDS, "child_seconds": CHILD_SECONDS,
        "minimum_scratch_free_bytes": SCRATCH_FREE, "scratch_boundary_limit_bytes": SCRATCH_LIMIT,
        "rss_boundary_limit_mib": RSS_LIMIT_MIB, "cache_state": "OS-cache-uncontrolled",
    }


class BaselineRun:
    def __init__(self, workspace: Path, binary: Path, scratch: Path, budget: SuiteBudget, ordinal: int):
        self.workspace, self.binary, self.scratch, self.budget = workspace, binary, scratch, budget
        self.ordinal = ordinal
        self.env = baseline_environment()
        self.preflight = new_section("preflight", 1, 20)
        self.anchor = new_section("anchor", 20)
        self.workloads: list[dict[str, Any]] = []
        self.next_ordinal = 1
        self.peak_mib: float | None = None
        self.failed_phase = "preflight"
        self.started_at_utc = utc_now()
        self.started_elapsed_ms = budget.elapsed_ms()

    def argv(self, command: list[str]) -> list[str]:
        result = []
        for value in command:
            if value == str(self.binary):
                result.append("binary")
            elif Path(value).is_absolute():
                path = Path(value).resolve()
                require(path.is_relative_to(self.scratch), "command references an unowned path")
                result.append("scratch/" + path.relative_to(self.scratch).as_posix())
            else:
                result.append(value)
        public_values(result)
        return result

    def invoke(
        self, section: dict[str, Any], command: list[str], operation: str, phase: str,
        trial: int, role: str, sample_index: int, *, query_class: str | None = None,
        generator_index: int | None = None, policy: str | None = None,
        legacy_metric: str | None = None, legacy_sample_index: int | None = None,
        check: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.failed_phase = f"{section['id']}/{phase}/{operation}"
        remaining = self.budget.remaining()
        record = {
            "ordinal": self.next_ordinal, "workload": section["id"], "operation": operation,
            "phase": phase, "trial": trial, "role": role, "sample_index": sample_index,
            "query_class": query_class, "generator_index": generator_index, "policy": policy,
            "legacy_metric": legacy_metric, "legacy_sample_index": legacy_sample_index,
            "argv": self.argv(command), "started_at_utc": utc_now(), "completed_at_utc": None,
            "process_wall_ms": None, "legacy_duration_ms": None, "stdout_bytes": None,
            "cli_reported_duration_ms": None, "exit_code": None, "outcome": "launch_failed",
            "memory": {"peak_rss_mib": None, "method": memory_method(), "interval_ms": 100,
                       "observation_count": 0, "unavailable_reason": "no_observations"},
            "correctness": None,
        }
        self.next_ordinal += 1
        section["observations"].append(record)
        try:
            result = process_lifecycle(command, self.workspace, self.env if env is None else env, timeout=min(CHILD_SECONDS, remaining), detailed=True)
        except (OSError, subprocess.SubprocessError):
            record["completed_at_utc"] = utc_now()
            raise ValueError("baseline: child launch or cleanup failed; attempt retained") from None
        peak = result["peak_rss_mb"]
        if peak is not None:
            self.peak_mib = max(self.peak_mib or 0, peak)
        record.update({
            "started_at_utc": result["started_at_utc"], "completed_at_utc": result["completed_at_utc"],
            "process_wall_ms": result["process_wall_ms"], "legacy_duration_ms": result["duration_ms"],
            "stdout_bytes": len(result["stdout_bytes"]), "exit_code": result["returncode"],
            "outcome": ("timeout_cleanup_incomplete" if result.get("cleanup_incomplete") else "timeout") if result["timed_out"] else "nonzero_exit",
            "memory": {"peak_rss_mib": peak, "method": memory_method(), "interval_ms": 100,
                       "observation_count": result["memory_observations"],
                       "unavailable_reason": "no_observations" if peak is None else None},
        })
        require(not result["timed_out"], "child timeout; attempt retained")
        require(result["returncode"] == 0, "child failed; attempt retained")
        record["outcome"] = "invalid_output"
        try:
            stdout = result["stdout_bytes"].decode("utf-8", errors="strict")
            require(stdout.endswith("\n") and len(stdout.split("\n")) == 2, "expected one complete output line")
            if operation.startswith("startup_"):
                require(stdout.startswith("agent-session-grep "), "incorrect version output")
                frame = None
                correctness = {"version_sha256": hashlib.sha256(result["stdout_bytes"]).hexdigest()}
            else:
                frame = strict_json(stdout)
                frame_success(frame, operation)
                cli_duration = frame.get("meta", {}).get("duration_ms")
                require(cli_duration is None or finite_number(cli_duration, integer=True), "invalid CLI pre-render duration")
                record["cli_reported_duration_ms"] = cli_duration
                record["outcome"] = "oracle_mismatch"
                correctness = check(frame) if check is not None else {"command_verified": operation}
                if operation in {"search", "context"} and section["id"] != "anchor":
                    require(record["stdout_bytes"] <= 4194304, "response exceeds explicit byte budget")
        except (TypeError, KeyError, IndexError, UnicodeError, json.JSONDecodeError):
            raise ValueError("baseline: malformed child response; attempt retained") from None
        record["correctness"] = correctness
        record["outcome"] = "suite_timeout"
        self.budget.remaining()
        record["outcome"] = "success"
        legacy = {"duration_ms": result["duration_ms"], "peak_rss_mb": peak, "stdout": stdout}
        if frame is not None:
            legacy["frame"] = frame
        return legacy

    def cli(self, section: dict[str, Any], db: Path, operation: str, phase: str, trial: int, role: str, sample_index: int, *args: str, **kwargs: Any) -> dict[str, Any]:
        command = [str(self.binary), "--db", str(db), "--output", "json", operation, *args]
        return self.invoke(section, command, operation, phase, trial, role, sample_index, **kwargs)

    def snapshot(self, section: dict[str, Any], db: Path, oracle: SyntheticOracle, phase: str, trial: int) -> None:
        retained = section["messages_per_file"] // 2 if phase == "shrink" else section["messages_per_file"]
        # Even mode=ro can create WAL/SHM files in a writable directory. Freeze
        # the post-child footprint before the independent census opens SQLite.
        files = [{"name": path.name, "bytes": path.stat().st_size} for path in sorted(db.parent.glob("catalog.db*")) if path.is_file()]
        census = oracle.scan(db, retained)
        corpus = copy.deepcopy(corpus_identity(section["file_count"], section["messages_per_file"], retained))
        require(tree_hash(oracle.paths, oracle.paths[0].parent) == corpus["tree_hash"], "phase corpus hash mismatch")
        section["snapshots"].append({
            "phase": phase, "trial": trial, "corpus": corpus, "census": census,
            "store": {"files": files, "total_bytes": sum(item["bytes"] for item in files),
                      "coverage": "catalog.db-and-present-sidecars-after-exit-no-explicit-checkpoint"},
        })

    def finish_section(self, section: dict[str, Any]) -> None:
        section["summaries"] = section_summaries(section)
        section["derived"] = section_derived(section)

    def run_preflight(self) -> None:
        section = self.preflight
        root = self.scratch / "preflight"
        paths, _ = write_dataset(root / "d", 1, 20)
        db, oracle = root / "catalog.db", SyntheticOracle(paths, 20)
        self.cli(section, db, "sync", "initial", 1, "verification", 1, *(str(path) for path in paths), check=lambda frame: sync_check(frame, 1, 20, "initial"))
        self.snapshot(section, db, oracle, "initial", 1)
        section["context_anchor"] = oracle.context_anchor()
        self.cli(section, db, "search", "intact", 1, "verification", 1, QUERIES[0], *SEARCH_OPTIONS, query_class="token", check=lambda frame: oracle.check_search(frame, "token"))
        for operation in ("show", "get"):
            self.cli(section, db, operation, "intact", 1, "verification", 1, oracle.bindings[1]["message_id"], generator_index=1, check=lambda frame, op=operation: oracle.check_read(frame, op, 1))
        for policy in ("mainline", "full"):
            self.cli(section, db, "context", "intact", 1, "verification", 1, oracle.bindings[0]["session_id"], "--policy", policy, *CONTEXT_OPTIONS, policy=policy, generator_index=0, check=lambda frame, selected=policy: oracle.check_context(frame, selected))
        self.cli(section, db, "sync", "noop", 1, "verification", 1, *(str(path) for path in paths), check=lambda frame: sync_check(frame, 1, 20, "noop"))
        self.snapshot(section, db, oracle, "noop", 1)
        shrink_dataset(paths)
        self.cli(section, db, "sync", "shrink", 1, "verification", 1, *(str(path) for path in paths), check=lambda frame: sync_check(frame, 1, 10, "shrink"))
        self.snapshot(section, db, oracle, "shrink", 1)
        self.finish_section(section)

    def query_scale(self, section: dict[str, Any], db: Path, oracle: SyntheticOracle) -> None:
        section["context_anchor"] = oracle.context_anchor()
        for query_class, query in zip(QUERY_CLASSES, QUERIES):
            for sample in range(1, 4):
                self.cli(section, db, "search", "intact", 3, "warmup", sample, query, *SEARCH_OPTIONS, query_class=query_class, check=lambda frame, cls=query_class: oracle.check_search(frame, cls))
        for sample in range(1, 101):
            for query_class, query in zip(QUERY_CLASSES, QUERIES):
                self.cli(section, db, "search", "intact", 3, "measured", sample, query, *SEARCH_OPTIONS, query_class=query_class, check=lambda frame, cls=query_class: oracle.check_search(frame, cls))
        for operation in ("show", "get"):
            for role, count in (("warmup", 3), ("measured", 100)):
                for sample in range(1, count + 1):
                    index = section["retrieval_indices"][sample - 1]
                    self.cli(section, db, operation, "intact", 3, role, sample, oracle.bindings[index]["message_id"], generator_index=index, check=lambda frame, op=operation, item=index: oracle.check_read(frame, op, item))
        for policy in ("mainline", "full"):
            for role, count in (("warmup", 3), ("measured", 100)):
                for sample in range(1, count + 1):
                    self.cli(section, db, "context", "intact", 3, role, sample, oracle.bindings[0]["session_id"], "--policy", policy, *CONTEXT_OPTIONS, policy=policy, generator_index=0, check=lambda frame, selected=policy: oracle.check_context(frame, selected))

    def run_scale(self, name: str, files: int) -> None:
        section = new_section(name, files)
        self.workloads.append(section)
        scale_root = self.scratch / name
        master, _ = write_dataset(scale_root / "master", files, 200)
        for trial in range(1, 4):
            self.budget.boundary(self.scratch, self.peak_mib)
            root = scale_root / f"t{trial}"
            shutil.copytree(master[0].parent, root / "d")
            paths = sorted((root / "d").glob("*.jsonl"))
            db, oracle = root / "catalog.db", SyntheticOracle(paths)
            for phase in ("initial", "noop"):
                self.cli(section, db, "sync", phase, trial, "measured", trial, *(str(path) for path in paths), check=lambda frame, step=phase: sync_check(frame, files, files * 200, step))
                self.snapshot(section, db, oracle, phase, trial)
            if trial == 3:
                self.query_scale(section, db, oracle)
            shrink_dataset(paths)
            self.cli(section, db, "sync", "shrink", trial, "measured", trial, *(str(path) for path in paths), check=lambda frame: sync_check(frame, files, files * 100, "shrink"))
            self.snapshot(section, db, oracle, "shrink", trial)
        self.finish_section(section)


def compatible_environment(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "captured_at_utc"}


def prepare_suite(
    workspace: Path, output: Path, scratch: Path, args: argparse.Namespace,
) -> tuple[Path, dict[str, Any], dict[str, Any], SuiteBudget, dict[str, Any]]:
    source = source_identity(workspace, args.expected_commit)
    config, target_directory, cargo_home = build_configuration(workspace, args)
    # Local-only path identity lets receipt reuse reject a changed Cargo cache
    # or target directory while public reports retain reviewed logical labels.
    build_paths_hash = json_hash({"cargo_home": str(cargo_home), "target_directory": str(target_directory), "scratch_parent": str(scratch.parent)})
    env = environment(workspace, args, config["rustc"])
    public_values(env)
    root = output.parent
    receipt_path, suite_path = root / "build-receipt.json", root / "suite.json"
    if args.baseline_run == 1:
        require(not receipt_path.exists() and not suite_path.exists(), "suite output already contains a frozen build or deadline")
        require(shutil.disk_usage(scratch).free >= SCRATCH_FREE, "less than 8 GiB scratch space available")
        binary, receipt = build_receipt(workspace, root, args, source, config, cargo_home)
        require(args.sqlite_version == receipt["sqlite"]["sqlite_version"], "operator SQLite version differs from this bundled build")
        env["sqlite_version_source"] = "locked bundled source + this build linkage; no direct CLI runtime query"
        largest_sync_preflight(binary, scratch)
        validate_build_receipt(receipt, source)
        write_json_new(receipt_path, {"sha256": json_hash(receipt), "receipt": receipt})
        # Build, source/link checks and command-line preflight are finished.
        # Exactly one monotonic deadline now covers all three driver processes.
        suite = {
            "suite_id": args.suite_id, "started_at_utc": utc_now(),
            "started_monotonic_ns": time.monotonic_ns(),
            "receipt_sha256": json_hash(receipt), "environment": compatible_environment(env),
            "child_policy": CHILD_POLICY, "build_context_paths_sha256": build_paths_hash,
        }
        write_json_new(suite_path, suite)
    else:
        require(receipt_path.is_file() and suite_path.is_file(), "originating run-1 build receipt and deadline required; no rebuild allowed")
        wrapper = strict_json(receipt_path.read_text(encoding="utf-8"))
        closed(wrapper, {"sha256", "receipt"}, "local receipt")
        receipt = wrapper["receipt"]
        validate_build_receipt(receipt, source)
        require(wrapper["sha256"] == json_hash(receipt), "local build receipt hash mismatch")
        require(receipt["configuration"] == config, "build environment or toolchain changed between runs")
        suite = strict_json(suite_path.read_text(encoding="utf-8"))
        env["sqlite_version_source"] = "locked bundled source + this build linkage; no direct CLI runtime query"
        require(args.sqlite_version == receipt["sqlite"]["sqlite_version"], "reused binary SQLite version differs from receipt")
        binary = root / ("baseline-cli.exe" if os.name == "nt" else "baseline-cli")
        previous = root / f"run-{args.baseline_run - 1:02d}.claim.json"
        require(previous.is_file(), "previous serial run is missing")
        claim = strict_json(previous.read_text(encoding="utf-8"))
        closed(claim, {"suite_id", "ordinal", "status", "output_directory", "report_sha256"}, "previous run claim")
        require(claim.get("status") == "complete" and claim.get("suite_id") == args.suite_id and type(claim.get("ordinal")) is int and claim["ordinal"] == args.baseline_run - 1, "previous run is incomplete")
        directory = claim["output_directory"]
        require(isinstance(directory, str) and directory not in {"", ".", ".."} and not Path(directory).drive and "/" not in directory and "\\" not in directory, "invalid previous output ownership")
        previous_report = root / claim["output_directory"] / "core-beta-benchmark-full.json"
        require(previous_report.is_file() and sha256_file(previous_report) == claim.get("report_sha256"), "previous report is missing or changed")
        prior = validate_report(previous_report, "full", quiet=True).get("baseline")
        require(isinstance(prior, dict) and prior["suite_id"] == args.suite_id and prior["run_ordinal"] == args.baseline_run - 1 and prior["build_receipt_sha256"] == json_hash(receipt), "previous report has incompatible baseline lineage")
    closed(suite, {"suite_id", "started_at_utc", "started_monotonic_ns", "receipt_sha256", "environment", "child_policy", "build_context_paths_sha256"}, "suite deadline")
    require(suite["suite_id"] == args.suite_id and suite["receipt_sha256"] == json_hash(receipt), "suite or receipt lineage mismatch")
    require(suite["environment"] == compatible_environment(env) and suite["child_policy"] == CHILD_POLICY, "measurement environment changed between runs")
    require(suite["build_context_paths_sha256"] == build_paths_hash, "Cargo cache or target directory changed between runs")
    require(binary.is_file() and sha256_file(binary) == receipt["binary_sha256"] and binary.stat().st_size == receipt["binary_size_bytes"], "frozen binary differs from build receipt")
    if args.baseline_run > 1:
        largest_sync_preflight(binary, scratch)
    require(source_identity(workspace, args.expected_commit) == source, "source changed during preflight")
    budget = SuiteBudget(suite["started_monotonic_ns"], suite["started_at_utc"])
    wall_elapsed = (datetime.now(timezone.utc) - utc_value(suite["started_at_utc"])).total_seconds()
    require(wall_elapsed >= 0 and abs(wall_elapsed - budget.elapsed_ms() / 1000) <= 5, "shared suite clock identity changed or became stale")
    budget.remaining()
    return binary, source, receipt, budget, env


TRACE_STAGES = {
    "cli:sync": {"prelude", "namespace", "capture", "jsonl_health", "stage", "assemble", "commit"},
    "adapter:catalog": {"validate_incoming", "noop_probe", "load_catalog_state", "merge_sources", "merge_stored", "tombstones", "manifest", "outbox_intent", "apply_commit", "finalize"},
    "adapter:commit": {"verify_outbox", "affected_sessions", "catalog_upserts", "fts_projection", "catalog_deletes", "relation_upserts", "source_replacements", "session_projection", "integrity_checks", "generation_activate", "tx_commit"},
    "adapter:fts": {"fts_projection_rows", "fts_ids_insert"},
    "adapter:bytes": set(),
}


def trace_aggregate(path: Path, phase: str, invocation: int) -> dict[str, Any]:
    require(path.is_file() and path.stat().st_size > 0, "trace output unavailable")
    records = [strict_json(line) for line in path.read_text(encoding="utf-8").split("\n") if line]
    labels: dict[str, dict[str, list[float]]] = {}
    order: list[str] = []
    pids = set()
    for record in records:
        closed(record, {"schema", "pid", "t_ms", "label", "stages_ms", "detail"}, "trace record")
        require(record["schema"] == "asg.index-trace/v1" and record["label"] in TRACE_STAGES, "unknown trace schema or label")
        require(finite_number(record["pid"], integer=True) and record["pid"] > 0 and finite_number(record["t_ms"]), "invalid trace process/time")
        pids.add(record["pid"])
        stages = record["stages_ms"]
        require(isinstance(stages, dict) and set(stages) <= TRACE_STAGES[record["label"]], "unknown trace stage")
        require(all(finite_number(value) for value in stages.values()), "invalid trace duration")
        values = labels.setdefault(record["label"], {})
        order.append(record["label"])
        for stage, value in stages.items():
            values.setdefault(stage, []).append(value)
    require(len(pids) == 1 and "cli:sync" in labels and "adapter:catalog" in labels, "incomplete trace invocation coverage")
    require(set(labels["cli:sync"]) == TRACE_STAGES["cli:sync"] and order.count("cli:sync") == 1, "incomplete CLI trace stages")
    if phase != "noop":
        for label in ("adapter:catalog", "adapter:commit", "adapter:fts"):
            require(label in labels and set(labels[label]) == TRACE_STAGES[label], "incomplete changed-sync trace stages")
    return {
        "phase": phase, "invocation_ordinal": invocation, "record_count": len(records),
        "label_order": order,
        "stages_ms": {label: {stage: {"raw_samples": values, "summary": baseline_summary(values)} for stage, values in stages.items()} for label, stages in labels.items()},
    }


def run_trace_trial(context: BaselineRun, output: Path) -> dict[str, Any]:
    """Separate local diagnosis after run 3; never a primary latency sample."""
    section = new_section("trace", 250)
    result: dict[str, Any] = {
        "status": "unavailable", "instrumentation_enabled": True, "phases": [],
        "reason": None,
        "limitations": ["Nested stage scopes overlap and must not be summed.", "Crate-local t_ms origins are not a shared timeline.", "adapter:bytes detail is not elapsed time or RSS and is not published."],
    }
    try:
        context.budget.boundary(context.scratch, context.peak_mib)
        root = context.scratch / "trace"
        paths, _ = write_dataset(root / "d", 250, 200)
        db, oracle = root / "catalog.db", SyntheticOracle(paths)
        for phase in ("initial", "noop", "shrink"):
            if phase == "shrink":
                shrink_dataset(paths)
            count = 25000 if phase == "shrink" else 50000
            trace = output / f"index-trace-{phase}.jsonl"
            require(not trace.exists(), "trace target already exists")
            ordinal = context.next_ordinal
            context.cli(section, db, "sync", phase, 1, "verification", 1, *(str(path) for path in paths), env=baseline_environment(trace=trace), check=lambda frame, step=phase, amount=count: sync_check(frame, 250, amount, step))
            context.snapshot(section, db, oracle, phase, 1)
            result["phases"].append(trace_aggregate(trace, phase, ordinal))
        context.budget.boundary(context.scratch, context.peak_mib)
        result["status"] = "available"
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        result["reason"] = "trace_unavailable_or_remaining_budget_exhausted"
    result["attempt"] = section
    write_json_new(output / "index-trace-observation.json", result)
    return result


def run_baseline(args: argparse.Namespace) -> Path:
    require(args.profile == "full" and type(args.baseline_run) is int and args.baseline_run in (1, 2, 3), "baseline requires full and ordinal 1, 2 or 3")
    require(isinstance(args.suite_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.suite_id) is not None, "baseline requires a safe suite ID")
    require(not args.binary, "external --binary is not allowed for a qualified baseline suite")
    require(digest_value(args.expected_commit, 40), "baseline requires the frozen expected source SHA")
    require(all(isinstance(getattr(args, name), str) and getattr(args, name).strip() and getattr(args, name) not in {"not_recorded", "not_exposed_by_cli"} for name in ("disk", "filesystem", "antivirus_state", "sqlite_version", "sqlite_version_source")), "baseline environment metadata required")
    workspace = Path(args.workspace).expanduser().resolve()
    output = Path(args.output_dir).expanduser().resolve()
    require(output.is_relative_to(workspace / "evidence-output") and output.parent != workspace / "evidence-output", "baseline outputs require a suite directory under ignored evidence-output")
    require(not output.is_symlink(), "output must not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    require(not any(output.iterdir()), "output directory already contains evidence; no clobber or automatic retry")
    claim_path = output.parent / f"run-{args.baseline_run:02d}.claim.json"
    claim = {"suite_id": args.suite_id, "ordinal": args.baseline_run, "status": "running", "output_directory": output.name, "report_sha256": None}
    write_json_new(claim_path, claim)
    attempt_path = output / "attempt.json"
    attempt: dict[str, Any] = {"schema_version": ATTEMPT_SCHEMA, "suite_id": args.suite_id, "ordinal": args.baseline_run, "status": "running", "failed_phase": "provenance", "reason": None, "sections": []}
    write_json_new(attempt_path, attempt)
    scratch: Path | None = None
    context: BaselineRun | None = None
    try:
        scratch = Path(tempfile.mkdtemp(prefix="ab-")).resolve()
        owner = {"root": str(scratch), "suite_id": args.suite_id, "ordinal": args.baseline_run}
        write_json_new(scratch / ".baseline-owner.json", owner)
        attempt["scratch_root"] = str(scratch)
        binary, source, receipt, budget, env = prepare_suite(workspace, output, scratch, args)
        context = BaselineRun(workspace, binary, scratch, budget, args.baseline_run)
        context.environment_data = env
        context.run_preflight()
        report = run_anchor(args, context)
        assert isinstance(report, dict)
        for name in scale_order(args.baseline_run):
            context.run_scale(name, dict(SCALES)[name])
        budget.boundary(scratch, context.peak_mib)
        after = source_identity(workspace, args.expected_commit)
        require(after == source and sha256_file(binary) == receipt["binary_sha256"], "source, harness or binary changed during measurement")
        report["environment"]["target_triple"] = receipt["configuration"]["target"]
        report["generated_at_utc"] = utc_now()
        report["baseline"] = {
            "schema_version": BASELINE_SCHEMA, "suite_id": args.suite_id, "run_ordinal": args.baseline_run,
            "started_at_utc": context.started_at_utc, "completed_at_utc": utc_now(),
            "suite_started_at_utc": budget.started_at_utc, "suite_started_monotonic_ns": budget.started_ns,
            "started_elapsed_ms": context.started_elapsed_ms, "completed_elapsed_ms": budget.elapsed_ms(),
            "source_before": source, "source_after": after,
            "build_receipt": receipt, "build_receipt_sha256": json_hash(receipt),
            "binary_use": "built_in_run_1" if args.baseline_run == 1 else "reused_run_1_receipt",
            "child_policy": copy.deepcopy(CHILD_POLICY), "plan": baseline_plan(args.baseline_run),
            "preflight": context.preflight, "anchor": context.anchor, "workloads": context.workloads,
            "coverage": {
                "complete": True, "independent_catalog_oracle": True,
                "failed_observations": 0, "trace": "separate-local-trial-after-primary-run-3",
                "limitations": [
                    "Synthetic positive first-page queries are not recall certification.",
                    "show/get are single-entity reads; context uses one generator-selected Session per scale.",
                    "Twenty startup and three sync samples have limited tail resolution.",
                    "Periodic process RSS is an approximate observation; absent observations remain null.",
                    "CLI duration is an integer-ms pre-render observation, not pure engine time.",
                    "Source SHA-256 is independently recomputed; native fingerprint alignment is checked across scan, document and evidence.",
                    "Boundary resource checks are guardrails, not OS quotas; process creation is not preemptible.",
                    "Build-derived SQLite evidence is not a CLI runtime version query or independent binary attestation.",
                ],
            },
        }
        report["limitations"] = [item for item in report["limitations"] if not item.startswith("The SQLite runtime version is operator-supplied")]
        report["limitations"].append("SQLite version is derived from the locked bundled source and this build's linkage receipt; no CLI runtime version query was performed.")
        report_path = output / "core-beta-benchmark-full.json"
        validate_report(report_path, "full", report_data=report, quiet=True)
        markdown = render_markdown(report)
        write_json_new(report_path, report)
        with report_path.with_suffix(".md").open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(markdown)
        trace = run_trace_trial(context, output) if args.baseline_run == 3 else None
        attempt.update({"status": "complete", "failed_phase": None, "reason": None, "sections": []})
        claim.update({"status": "complete", "report_sha256": sha256_file(report_path)})
        if trace is None or trace["status"] == "available":
            cleanup_scratch(scratch, owner)
            attempt["scratch_root"] = None
        else:
            attempt["trace_scratch_retained"] = True
        replace_owned_json(attempt_path, attempt)
        replace_owned_json(claim_path, claim)
        print(report_path)
        return report_path
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError, KeyboardInterrupt) as error:
        attempt.update({
            "status": "failed", "failed_phase": context.failed_phase if context is not None else "provenance",
            "reason": str(error) if str(error).startswith("baseline:") and len(str(error)) < 240 else type(error).__name__,
            "sections": [context.preflight, context.anchor, *context.workloads] if context is not None else [],
        })
        claim["status"] = "failed"
        replace_owned_json(attempt_path, attempt)
        replace_owned_json(claim_path, claim)
        raise ValueError("baseline: incomplete attempt retained; no successful suite result") from error


def startup_samples(binary: Path, workspace: Path, count: int, scratch: Path, observe: Callable[..., dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    def execute(command: list[str], phase: str, role: str, index: int) -> dict[str, Any]:
        return run_process(command, workspace) if observe is None else observe(command, phase, role, index)

    for index in range(3):
        execute([str(binary), "--version"], "warm", "warmup", index + 1)
    warm = [execute([str(binary), "--version"], "warm", "measured", index + 1) for index in range(count)]
    cold: list[dict[str, Any]] = []
    for index in range(count):
        suffix = binary.suffix
        copy = scratch / f"startup-cold-{index:03d}{suffix}"
        shutil.copy2(binary, copy)
        cold.append(execute([str(copy), "--version"], "cold", "measured", index + 1))
        copy.unlink()
    return cold, warm


def run_benchmark(args: argparse.Namespace) -> Path:
    if getattr(args, "baseline_run", None) is not None or getattr(args, "suite_id", None) is not None:
        return run_baseline(args)
    result = run_anchor(args)
    assert isinstance(result, Path)
    return result


def run_anchor(args: argparse.Namespace, baseline: BaselineRun | None = None) -> Path | dict[str, Any]:
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
    binary = resolve_binary(workspace, args) if baseline is None else baseline.binary
    binary_provenance = "caller_supplied_prebuilt" if args.binary or (baseline is not None and baseline.ordinal > 1) else "built_by_harness_from_workspace"

    scratch_context = tempfile.TemporaryDirectory(prefix="agent-session-grep-evidence-") if baseline is None else nullcontext(str(baseline.scratch / "anchor"))
    with scratch_context as temp_name:
        scratch = Path(temp_name)
        scratch.mkdir(parents=True, exist_ok=True)
        master = scratch / "dataset-master"
        dataset_files, all_ids = write_dataset(master, profile["files"], profile["messages_per_file"])
        dataset_bytes = directory_size(dataset_files)
        dataset_digest = tree_hash(dataset_files, master)
        observe = None
        if baseline is not None:
            def observe(command: list[str], phase: str, role: str, index: int) -> dict[str, Any]:
                return baseline.invoke(
                    baseline.anchor, command, "startup_" + phase, "startup", 0, role, index,
                    legacy_metric="cli_startup_" + phase + "_latency_ms" if role == "measured" else None,
                    legacy_sample_index=index if role == "measured" else None,
                )
        cold, warm = startup_samples(binary, workspace, profile["startup"], scratch, observe)

        def execute(db: Path, operation: str, phase: str, trial: int, index: int, *arguments: str, oracle: SyntheticOracle | None = None, generator_index: int | None = None) -> dict[str, Any]:
            if baseline is None:
                return cli(binary, workspace, db, operation, *arguments)
            check = None
            query_class = None
            metric_name = operation + "_latency_ms"
            if operation == "sync":
                count = profile["files"] * (profile["messages_per_file"] // 2 if phase == "shrink" else profile["messages_per_file"])
                check = lambda frame: sync_check(frame, profile["files"], count, phase)
                metric_name = phase + "_sync_latency_ms"
            elif operation == "search":
                assert oracle is not None
                query_class = QUERY_CLASSES[(index - 1) % len(QUERIES)]
                check = lambda frame: oracle.check_search(frame, query_class)
            elif operation in {"show", "get"}:
                assert oracle is not None and generator_index is not None
                check = lambda frame: oracle.check_read(frame, operation, generator_index)
            return baseline.cli(
                baseline.anchor, db, operation, phase, trial, "verification" if operation == "doctor" else "measured", index, *arguments,
                check=check, query_class=query_class, generator_index=generator_index,
                legacy_metric=metric_name if operation != "doctor" else None,
                legacy_sample_index=index if operation != "doctor" else None,
            )

        initial_samples: list[dict[str, Any]] = []
        noop_samples: list[dict[str, Any]] = []
        shrink_samples: list[dict[str, Any]] = []
        initial_store_bytes_samples: list[int] = []
        initial_store_files: list[str] = []
        final_db: Path | None = None
        final_trial: Path | None = None
        final_oracle: SyntheticOracle | None = None
        for trial_number in range(profile["sync"]):
            if baseline is not None:
                baseline.budget.boundary(baseline.scratch, baseline.peak_mib)
            trial = scratch / f"sync-trial-{trial_number:03d}"
            shutil.copytree(master, trial / "dataset")
            paths = sorted((trial / "dataset").glob("*.jsonl"))
            db = trial / "catalog.db"
            oracle = SyntheticOracle(paths, profile["messages_per_file"]) if baseline is not None else None
            initial_samples.append(execute(db, "sync", "initial", trial_number + 1, trial_number + 1, *(str(path) for path in paths)))
            initial_files = list(trial.glob("catalog.db*"))
            initial_store_bytes_samples.append(directory_size(initial_files))
            initial_store_files = sorted(path.name for path in initial_files)
            if baseline is not None:
                baseline.snapshot(baseline.anchor, db, oracle, "initial", trial_number + 1)
            noop_samples.append(execute(db, "sync", "noop", trial_number + 1, trial_number + 1, *(str(path) for path in paths)))
            if baseline is not None:
                baseline.snapshot(baseline.anchor, db, oracle, "noop", trial_number + 1)
            shrink_dataset(paths)
            shrink_samples.append(execute(db, "sync", "shrink", trial_number + 1, trial_number + 1, *(str(path) for path in paths)))
            if baseline is not None:
                baseline.snapshot(baseline.anchor, db, oracle, "shrink", trial_number + 1)
            final_db, final_trial = db, trial
            final_oracle = oracle

        if final_db is None or final_trial is None:
            raise RuntimeError("profile must request at least one sync sample")

        query_count = profile["query"]
        search_samples = [execute(final_db, "search", "post_shrink", 3, index + 1, QUERIES[index % len(QUERIES)], oracle=final_oracle) for index in range(query_count)]
        for index, sample in enumerate(search_samples):
            if not sample["frame"]["data"].get("hits"):
                raise RuntimeError(f"search query returned no synthetic hit: {QUERIES[index % len(QUERIES)]}")
        retained_ids = [all_ids[file_index * profile["messages_per_file"] + local_index]
                        for file_index in range(profile["files"])
                        for local_index in range(max(1, profile["messages_per_file"] // 2))]
        retained_indices = [all_ids.index(identity) for identity in retained_ids[:query_count]]
        show_samples = [execute(final_db, "show", "post_shrink", 3, index + 1, retained_ids[index % len(retained_ids)], oracle=final_oracle, generator_index=retained_indices[index % len(retained_indices)]) for index in range(query_count)]
        get_samples = [execute(final_db, "get", "post_shrink", 3, index + 1, retained_ids[index % len(retained_ids)], oracle=final_oracle, generator_index=retained_indices[index % len(retained_indices)]) for index in range(query_count)]
        doctor = execute(final_db, "doctor", "post_shrink", 3, 1)

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
            "environment": environment(workspace, args) if baseline is None else copy.deepcopy(baseline.environment_data),
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
        if binary_provenance == "caller_supplied_prebuilt":
            report["limitations"].append(
                "The measured binary was caller-supplied; its hash is authoritative, but source-to-binary linkage is not independently attested."
            )

    if baseline is not None:
        baseline.finish_section(baseline.anchor)
        return report
    report_path = output_dir / f"core-beta-benchmark-{args.profile}.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    validate_report(report_path, args.profile)
    markdown_path = report_path.with_suffix(".md")
    markdown_path.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    print(report_path)
    return report_path


def exact_json(actual: Any, expected: Any, label: str) -> None:
    # JSON equality is type-aware (unlike True == 1 in Python).
    require(json_hash(actual) == json_hash(expected), label)


def validate_source(value: Any, commit: str) -> None:
    closed(value, {
        "commit", "harness_commit", "checker_commit", "harness_path", "harness_sha256", "checker_sha256",
        "cargo_lock_sha256", "cargo_manifest_sha256", "repository", "cleanliness",
    }, "source")
    require(digest_value(commit, 40) and value["commit"] == value["harness_commit"] == value["checker_commit"] == commit, "source/harness/checker commit mismatch")
    require(value["harness_path"] == HARNESS_PATH and value["repository"] == "Lain-in-coding/agent-session-grep", "wrong harness or source repository")
    for field in ("harness_sha256", "checker_sha256", "cargo_lock_sha256", "cargo_manifest_sha256"):
        require(digest_value(value[field]), "invalid source input hash")
    require(value["harness_sha256"] == value["checker_sha256"], "checker differs from harness")
    exact_json(value["cleanliness"], {"tracked": "clean", "index": "clean", "untracked": "clean"}, "source is not clean")


def validate_build_receipt(receipt: Any, source: dict[str, Any]) -> None:
    try:
        _validate_build_receipt(receipt, source)
    except (KeyError, TypeError, IndexError, AttributeError, OverflowError, RecursionError):
        raise ValueError("baseline: malformed build receipt container or value") from None


def _validate_build_receipt(receipt: Any, source: dict[str, Any]) -> None:
    closed(receipt, {
        "schema_version", "origin_run", "source", "configuration", "cargo_version", "command", "features",
        "release_profile", "artifact_was_cached", "artifact_relative_to_target", "binary_sha256", "binary_size_bytes", "sqlite", "linkage",
    }, "build receipt")
    require(receipt["schema_version"] == BUILD_SCHEMA and type(receipt["origin_run"]) is int and receipt["origin_run"] == 1, "unsupported build receipt")
    exact_json(receipt["source"], source, "build source mismatch")
    validate_source(source, source["commit"])
    require(digest_value(receipt["binary_sha256"]) and finite_number(receipt["binary_size_bytes"], integer=True) and receipt["binary_size_bytes"] > 0, "invalid built binary identity")
    require(receipt["linkage"] == "harness-build-receipt-not-independent-attestation", "unsupported binary linkage assertion")
    exact_json(receipt["command"], ["cargo", "build", "--locked", "--release", "-p", "agent-session-grep-cli", "--message-format=json"], "unexpected build command")
    require(isinstance(receipt["cargo_version"], str) and re.fullmatch(r"cargo [0-9][^\r\n]{0,180}", receipt["cargo_version"]) is not None, "invalid Cargo version")
    require(type(receipt["artifact_was_cached"]) is bool, "missing Cargo artifact cache observation")
    artifact = receipt["artifact_relative_to_target"]
    require(isinstance(artifact, str) and re.fullmatch(r"(?:[a-z0-9_-]+/)?release/agent-session-grep(?:\.exe)?", artifact) is not None, "invalid Cargo artifact path")
    features = receipt["features"]
    require(isinstance(features, list) and all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", item) for item in features) and sorted(set(features)) == features, "invalid CLI feature set")
    profile = closed(receipt["release_profile"], {"opt_level", "debuginfo", "debug_assertions", "overflow_checks", "test"}, "release profile")
    require(profile["opt_level"] == "3" and profile["debug_assertions"] is False and profile["test"] is False and type(profile["overflow_checks"]) is bool, "unexpected release profile settings")
    require(profile["debuginfo"] is None or (type(profile["debuginfo"]) is int and profile["debuginfo"] in (0, 1, 2)) or profile["debuginfo"] in ("line-directives-only", "line-tables-only"), "invalid release debug information")
    config = closed(receipt["configuration"], {"target", "rustc", "cargo_tool_sha256", "rustc_tool_sha256", "environment", "cargo_configuration", "compiler_link_overrides"}, "build configuration")
    require(isinstance(config["target"], str) and re.fullmatch(r"[a-z0-9_-]{5,100}", config["target"]) is not None, "invalid target triple")
    require(isinstance(config["rustc"], str) and f"host: {config['target']}" in config["rustc"].split("\n"), "rustc target mismatch")
    require(digest_value(config["cargo_tool_sha256"]) and digest_value(config["rustc_tool_sha256"]), "missing build-tool identity")
    require(config["cargo_configuration"] == config["compiler_link_overrides"] == "none", "unresolved build overrides")
    variables = closed(config["environment"], {"CARGO_BUILD_TARGET", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR"}, "build environment")
    require(variables["CARGO_BUILD_TARGET"] in (None, config["target"]), "build target override mismatch")
    require(variables["CARGO_BUILD_JOBS"] is None or (isinstance(variables["CARGO_BUILD_JOBS"], str) and re.fullmatch(r"[1-9][0-9]{0,2}", variables["CARGO_BUILD_JOBS"])), "invalid build jobs override")
    require(variables["CARGO_TARGET_DIR"] in {"source-root/target", "explicit-build-target"}, "invalid target directory policy")
    sqlite = closed(receipt["sqlite"], {"package", "package_version", "archive_sha256", "sqlite_version", "header_sha256", "source_sha256", "build_script_sha256", "method", "runtime_query", "features", "linked_libraries", "native_library_sha256", "native_library_size_bytes"}, "SQLite proof")
    require(sqlite["package"] == "libsqlite3-sys" and sqlite["method"] == "locked-bundled-source-and-build-linkage" and sqlite["runtime_query"] is False, "unproved SQLite linkage")
    for key in ("package_version", "sqlite_version"):
        require(isinstance(sqlite[key], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sqlite[key]), "invalid SQLite version")
    for key in ("archive_sha256", "header_sha256", "source_sha256", "build_script_sha256", "native_library_sha256"):
        require(digest_value(sqlite[key]), "missing SQLite build hash")
    require(finite_number(sqlite["native_library_size_bytes"], integer=True) and sqlite["native_library_size_bytes"] > 0, "missing native SQLite library")
    sql_features = sqlite["features"]
    require(isinstance(sql_features, list) and all(isinstance(item, str) for item in sql_features) and sorted(set(sql_features)) == sql_features and "bundled" in sql_features, "invalid bundled SQLite features")
    require(not any("sqlcipher" in item or "loadable_extension" in item for item in sql_features), "external SQLite features are unsupported")
    exact_json(sqlite["linked_libraries"], ["static=sqlite3"], "SQLite is not linked as the bundled static library")
    public_values(receipt)


def expected_observation_sequence(section: dict[str, Any], binary_suffix: str = ".exe") -> list[dict[str, Any]]:
    """The closed v1 sampling order; no processes, source generation or I/O."""
    name, files = section["id"], section["file_count"]
    expected: list[dict[str, Any]] = []

    def append(operation: str, phase: str, trial: int, role: str, sample: int, query_class: str | None = None, index: int | None = None, policy: str | None = None) -> None:
        metric_name = None
        if name == "anchor" and role == "measured":
            if operation.startswith("startup_"):
                metric_name = "cli_" + operation + "_latency_ms"
            elif operation == "sync":
                metric_name = phase + "_sync_latency_ms"
            else:
                metric_name = operation + "_latency_ms"
        record = {
            "operation": operation, "phase": phase, "trial": trial, "role": role, "sample_index": sample,
            "query_class": query_class, "generator_index": index, "policy": policy,
            "legacy_metric": metric_name, "legacy_sample_index": sample if metric_name else None,
        }
        if operation.startswith("startup_"):
            binary = f"scratch/anchor/startup-cold-{sample - 1:03d}{binary_suffix}" if operation == "startup_cold" else "binary"
            argv = [binary, "--version"]
        else:
            if name == "anchor":
                root, directory = f"scratch/anchor/sync-trial-{trial - 1:03d}", "dataset"
            elif name == "preflight":
                root, directory = "scratch/preflight", "d"
            else:
                root, directory = f"scratch/{name}/t{trial}", "d"
            argv = ["binary", "--db", f"{root}/catalog.db", "--output", "json", operation]
            if operation == "sync":
                argv += [f"{root}/{directory}/session-{file_index:04d}.jsonl" for file_index in range(files)]
            elif operation == "search":
                argv += [QUERIES[QUERY_CLASSES.index(query_class)]]
                if name != "anchor":
                    argv += SEARCH_OPTIONS
            elif operation in {"show", "get"}:
                argv += [f"msg_v1_00000000-0000-4000-8000-{index:012d}"]
            elif operation == "context":
                argv += [section["context_anchor"]["session_id"], "--policy", policy, *CONTEXT_OPTIONS]
        record["argv"] = argv
        expected.append(record)

    if name == "preflight":
        append("sync", "initial", 1, "verification", 1)
        append("search", "intact", 1, "verification", 1, "token")
        for operation in ("show", "get"):
            append(operation, "intact", 1, "verification", 1, index=1)
        for policy in ("mainline", "full"):
            append("context", "intact", 1, "verification", 1, index=0, policy=policy)
        append("sync", "noop", 1, "verification", 1)
        append("sync", "shrink", 1, "verification", 1)
    elif name == "anchor":
        for sample in range(1, 4):
            append("startup_warm", "startup", 0, "warmup", sample)
        for operation in ("startup_warm", "startup_cold"):
            for sample in range(1, 21):
                append(operation, "startup", 0, "measured", sample)
        for trial in range(1, 4):
            for phase in ("initial", "noop", "shrink"):
                append("sync", phase, trial, "measured", trial)
        for sample in range(1, 101):
            append("search", "post_shrink", 3, "measured", sample, QUERY_CLASSES[(sample - 1) % 5])
        for operation in ("show", "get"):
            for sample in range(1, 101):
                append(operation, "post_shrink", 3, "measured", sample, index=sample - 1)
        append("doctor", "post_shrink", 3, "verification", 1)
    else:
        for trial in range(1, 4):
            for phase in ("initial", "noop"):
                append("sync", phase, trial, "measured", trial)
            if trial == 3:
                for query_class in QUERY_CLASSES:
                    for sample in range(1, 4):
                        append("search", "intact", 3, "warmup", sample, query_class)
                for sample in range(1, 101):
                    for query_class in QUERY_CLASSES:
                        append("search", "intact", 3, "measured", sample, query_class)
                for operation in ("show", "get"):
                    for role, count in (("warmup", 3), ("measured", 100)):
                        for sample in range(1, count + 1):
                            append(operation, "intact", 3, role, sample, index=retrieval_indices(files)[sample - 1])
                for policy in ("mainline", "full"):
                    for role, count in (("warmup", 3), ("measured", 100)):
                        for sample in range(1, count + 1):
                            append("context", "intact", 3, role, sample, index=0, policy=policy)
            append("sync", "shrink", trial, "measured", trial)
    return expected


def validate_context_anchor(section: dict[str, Any]) -> None:
    anchor, size = section["context_anchor"], section["messages_per_file"]
    if section["id"] == "anchor":
        require(anchor is None, "legacy anchor must not claim context samples")
        return
    closed(anchor, {"generator_file", "session_id", "source_document_id", "source_fingerprint", "source_sha256", "members", "mainline_order", "full_order"}, "context anchor")
    require(type(anchor["generator_file"]) is int and anchor["generator_file"] == 0, "context anchor must use generator file zero")
    for key, prefix in (("session_id", "ses_v1_"), ("source_document_id", "doc_v1_")):
        require(isinstance(anchor[key], str) and re.fullmatch(prefix + r"[0-9a-f]{32}", anchor[key]) is not None, "invalid context wire identity")
    require(isinstance(anchor["source_fingerprint"], str) and re.fullmatch(r"[A-Za-z0-9:_-]{16,128}", anchor["source_fingerprint"]) is not None, "invalid context source fingerprint")
    expected_lines = fixture_lines(0, size, size)
    require(anchor["source_sha256"] == hashlib.sha256(b"\n".join(expected_lines) + b"\n").hexdigest(), "context source hash mismatch")
    require(isinstance(anchor["members"], list) and len(anchor["members"]) == size, "incorrect context anchor membership count")
    placements = set()
    offset = 0
    for index, member in enumerate(anchor["members"]):
        closed(member, {"generator_index", "message_id", "placement_id", "session_id", "source_document_id", "source_ordinal", "byte_start", "byte_end", "source_fingerprint"}, "context member")
        require(isinstance(member["placement_id"], str) and re.fullmatch(r"plc_v1_[0-9a-f]{32}", member["placement_id"]) is not None and member["placement_id"] not in placements, "invalid or duplicate context placement")
        placements.add(member["placement_id"])
        expected = {
            "generator_index": index, "message_id": f"msg_v1_00000000-0000-4000-8000-{index:012d}",
            "placement_id": member["placement_id"], "session_id": anchor["session_id"],
            "source_document_id": anchor["source_document_id"], "source_fingerprint": anchor["source_fingerprint"],
            "source_ordinal": index, "byte_start": offset, "byte_end": offset + len(expected_lines[index]),
        }
        exact_json(member, expected, "context member differs from fixture source/identity")
        offset += len(expected_lines[index]) + 1
    for policy in ("mainline", "full"):
        exact_json(anchor[policy + "_order"], fixture_context_order(list(range(size)), size, policy), "context policy order differs from fixture oracle")


def expected_census(files: int, per_file: int, retained: int, bindings_hash: str) -> dict[str, Any]:
    return {
        "messages": files * retained, "placements": files * retained, "sessions": files,
        "documents": files, "sources": files, "edges": files * (retained - math.ceil(retained / 10)),
        "catalog_entities": files * (retained + 2), "fts_messages": files * retained,
        "source_placement_claims": files * retained, "source_entity_claims": files * (retained + 2),
        "generation": 1 if retained == per_file else 2, "retained_verified": files * retained,
        "removed_verified": files * (per_file - retained), "bindings_sha256": bindings_hash,
    }


def validate_snapshots(section: dict[str, Any]) -> None:
    snapshots = section["snapshots"]
    trials = 1 if section["id"] == "preflight" else 3
    require(isinstance(snapshots, list) and len(snapshots) == 3 * trials, "incorrect phase snapshot count")
    bindings: dict[tuple[int, str], str] = {}
    for snapshot, (trial, phase) in zip(snapshots, ((trial, phase) for trial in range(1, trials + 1) for phase in ("initial", "noop", "shrink"))):
        closed(snapshot, {"phase", "trial", "corpus", "census", "store"}, "phase snapshot")
        require(type(snapshot["trial"]) is int and snapshot["trial"] == trial and snapshot["phase"] == phase, "wrong snapshot trial, phase or order")
        retained = section["messages_per_file"] // 2 if phase == "shrink" else section["messages_per_file"]
        exact_json(snapshot["corpus"], corpus_identity(section["file_count"], section["messages_per_file"], retained), "phase corpus shape, count, bytes or hash mismatch")
        census = snapshot["census"]
        require(isinstance(census, dict) and digest_value(census.get("bindings_sha256")), "invalid verified census binding")
        exact_json(census, expected_census(section["file_count"], section["messages_per_file"], retained, census["bindings_sha256"]), "incorrect oracle census or generation")
        phase_key = (trial, "intact" if phase != "shrink" else phase)
        if phase_key in bindings:
            require(census["bindings_sha256"] == bindings[phase_key], "immediate noop identities changed")
        bindings[phase_key] = census["bindings_sha256"]
        store = closed(snapshot["store"], {"files", "total_bytes", "coverage"}, "store snapshot")
        require(store["coverage"] == "catalog.db-and-present-sidecars-after-exit-no-explicit-checkpoint", "incorrect store coverage")
        files = store["files"]
        require(isinstance(files, list) and 0 < len(files) <= 12, "invalid store file count")
        names = []
        for entry in files:
            closed(entry, {"name", "bytes"}, "store file")
            require(isinstance(entry["name"], str) and re.fullmatch(r"catalog\.db(?:[.-][a-zA-Z0-9._-]+)?", entry["name"]) is not None, "invalid store file name")
            require(finite_number(entry["bytes"], integer=True), "invalid store file byte count")
            names.append(entry["name"])
        require(names == sorted(set(names)) and "catalog.db" in names, "duplicate or missing store file")
        require(finite_number(store["total_bytes"], integer=True) and 0 < store["total_bytes"] <= SCRATCH_LIMIT and store["total_bytes"] == sum(entry["bytes"] for entry in files), "invalid store total bytes")


def validate_correctness(record: dict[str, Any], section: dict[str, Any]) -> None:
    operation, phase = record["operation"], record["phase"]
    actual = record["correctness"]
    require(isinstance(actual, dict), "missing per-invocation correctness observation")
    generation = 2 if phase in {"post_shrink", "shrink"} else 1
    if operation.startswith("startup_"):
        closed(actual, {"version_sha256"}, "version check")
        require(digest_value(actual["version_sha256"]), "invalid version observation hash")
    elif operation == "sync":
        count = section["file_count"] * (section["messages_per_file"] // 2 if phase == "shrink" else section["messages_per_file"])
        expected = {
            "sources": section["file_count"], "emitted": 0 if phase == "noop" else count,
            "messages": 0 if phase == "noop" else count, "committed": 0 if phase == "noop" else count,
            "unchanged": count if phase == "noop" else 0, "retained": 0, "deferred": 0,
            "skipped": 0, "diagnostics": 0, "generation": generation,
        }
        exact_json(actual, expected, "incorrect observed sync accounting")
    elif operation == "search":
        closed(actual, {"generation", "hit_count", "result_ids_sha256"}, "search check")
        require(type(actual["generation"]) is int and actual["generation"] == generation and type(actual["hit_count"]) is int and actual["hit_count"] == 20 and digest_value(actual["result_ids_sha256"]), "incorrect search observation")
    elif operation in {"show", "get"}:
        exact_json(actual, {"generator_index": record["generator_index"], "message_id": f"msg_v1_00000000-0000-4000-8000-{record['generator_index']:012d}"}, "incorrect single-entity identity")
    elif operation == "context":
        order = section["context_anchor"][record["policy"] + "_order"]
        exact_json(actual, {"generation": generation, "message_count": len(order), "order_sha256": json_hash(order), "evidence_count": len(order)}, "incorrect context graph or evidence observation")
    else:
        exact_json(actual, {"command_verified": "doctor"}, "incorrect doctor observation")


def validate_section(section: Any, name: str, files: int, per_file: int, baseline: dict[str, Any], suffix: str) -> list[dict[str, Any]]:
    closed(section, {"id", "file_count", "messages_per_file", "query_phase", "query_trial", "snapshots", "observations", "context_anchor", "retrieval_indices", "summaries", "derived"}, "workload")
    shape = {"id": name, "file_count": files, "messages_per_file": per_file, "query_phase": "post_shrink" if name == "anchor" else "intact", "query_trial": 1 if name == "preflight" else 3}
    exact_json({key: section[key] for key in shape}, shape, "wrong workload identity, size or query phase")
    exact_json(section["retrieval_indices"], [1] if name == "preflight" else list(range(100)) if name == "anchor" else retrieval_indices(files), "incorrect fixed entity selection")
    validate_snapshots(section)
    validate_context_anchor(section)
    expected = expected_observation_sequence(section, suffix)
    observations = section["observations"]
    require(isinstance(observations, list) and len(observations) == len(expected), "missing or extra invocation coverage")
    run_start, run_end = utc_value(baseline["started_at_utc"]), utc_value(baseline["completed_at_utc"])
    for record, planned in zip(observations, expected):
        closed(record, set(planned) | {"ordinal", "workload", "started_at_utc", "completed_at_utc", "process_wall_ms", "legacy_duration_ms", "stdout_bytes", "cli_reported_duration_ms", "exit_code", "outcome", "memory", "correctness"}, "invocation")
        exact_json({key: record[key] for key in planned}, planned, "invocation order, phase, count, anchor or argv differs from plan")
        require(record["workload"] == name and finite_number(record["ordinal"], integer=True) and record["ordinal"] > 0, "incorrect invocation identity")
        require(type(record["exit_code"]) is int and record["exit_code"] == 0 and record["outcome"] == "success", "failed invocation cannot qualify a report")
        for key in ("process_wall_ms", "legacy_duration_ms"):
            require(finite_number(record[key]) and rounded(record[key]) == record[key], "invalid or unrounded process duration")
        require(record["process_wall_ms"] <= record["legacy_duration_ms"] and record["process_wall_ms"] <= CHILD_SECONDS * 1000, "invalid timing boundary or child deadline")
        require(finite_number(record["stdout_bytes"], integer=True) and record["stdout_bytes"] > 0, "invalid stdout byte count")
        if name != "anchor" and record["operation"] in {"search", "context"}:
            require(record["stdout_bytes"] <= 4194304, "response byte budget exceeded")
        cli_time = record["cli_reported_duration_ms"]
        require(cli_time is None or finite_number(cli_time, integer=True), "invalid CLI pre-render observation")
        if record["operation"].startswith("startup_"):
            require(cli_time is None, "startup must not invent a Robot duration")
        start, end = utc_value(record["started_at_utc"]), utc_value(record["completed_at_utc"])
        require(run_start <= start <= end <= run_end, "invocation UTC interval outside run")
        memory = closed(record["memory"], {"peak_rss_mib", "method", "interval_ms", "observation_count", "unavailable_reason"}, "memory observation")
        require(memory["method"] == baseline["plan"]["memory_method"] and type(memory["interval_ms"]) is int and memory["interval_ms"] == 100 and finite_number(memory["observation_count"], integer=True), "invalid memory observation method/count")
        if memory["peak_rss_mib"] is None:
            require(memory["observation_count"] == 0 and memory["unavailable_reason"] == "no_observations", "missing memory reason or alignment")
        else:
            require(finite_number(memory["peak_rss_mib"]) and rounded(memory["peak_rss_mib"]) == memory["peak_rss_mib"] and memory["peak_rss_mib"] <= RSS_LIMIT_MIB and memory["observation_count"] > 0 and memory["unavailable_reason"] is None, "invalid observed memory or guardrail")
        validate_correctness(record, section)
    exact_json(section["summaries"], section_summaries(section), "raw-derived workload summaries differ")
    exact_json(section["derived"], section_derived(section), "raw-derived throughput or store ratios differ")
    return observations


def validate_anchor_links(report: dict[str, Any]) -> None:
    anchor = report["baseline"]["anchor"]
    initial_corpus = corpus_identity(20, 200, 200)
    dataset = report["dataset"]
    require(dataset.get("dataset_hash") == initial_corpus["tree_hash"] and dataset.get("source_bytes") == initial_corpus["source_bytes"] and dataset.get("query_set") == QUERIES, "legacy dataset differs from anchor input")
    measured: dict[str, list[dict[str, Any]]] = {}
    for record in anchor["observations"]:
        if record["legacy_metric"] is not None:
            measured.setdefault(record["legacy_metric"], []).append(record)
    require(len(measured) == 8, "incomplete legacy metric links")
    for name, records in measured.items():
        metric_data = report["metrics"][name]
        exact_json(metric_data["raw_samples"], [record["legacy_duration_ms"] for record in records], "legacy/corrected invocation link mismatch")
        exact_json(metric_data["peak_rss_mb_raw_samples"], [record["memory"]["peak_rss_mib"] for record in records if record["memory"]["peak_rss_mib"] is not None], "legacy memory alignment mismatch")
    initial_durations = [record["legacy_duration_ms"] for record in measured["initial_sync_latency_ms"]]
    require(all(value > 0 for value in initial_durations), "initial legacy sync duration must be positive")
    exact_json(report["metrics"]["initial_index_throughput_mb_s"]["raw_samples"], [rounded(initial_corpus["source_bytes"] / 1024**2 / (value / 1000)) for value in initial_durations], "legacy throughput differs from same-invocation durations")
    sizes = report["sizes"]
    initial = [item["store"] for item in anchor["snapshots"] if item["phase"] == "initial"]
    shrink = anchor["snapshots"][-1]["store"]
    exact_json(sizes["initial_store_bytes_raw_samples"], [store["total_bytes"] for store in initial], "legacy initial store samples differ from snapshots")
    require(sizes["initial_store_bytes_including_sidecars"] == initial[-1]["total_bytes"] and sizes["post_shrink_store_bytes_including_sidecars"] == shrink["total_bytes"], "legacy store phase mismatch")
    exact_json(sizes["initial_store_files"], [item["name"] for item in initial[-1]["files"]], "legacy initial store files differ")
    exact_json(sizes["post_shrink_store_files"], [item["name"] for item in shrink["files"]], "legacy shrink store files differ")
    require(sizes["index_size_ratio"] == rounded(initial[-1]["total_bytes"] / initial_corpus["source_bytes"]), "legacy index size ratio mismatch")
    doctor = anchor["observations"][-1]
    observation = report["recovery"]["observation"]
    require(observation.get("doctor_open_duration_ms") == doctor["legacy_duration_ms"] and type(observation.get("active_generation")) is int and observation["active_generation"] == 2, "doctor observation differs from anchor")


def validate_baseline_extension(report: dict[str, Any]) -> None:
    """Conditional closed contract; keep diagnostics bounded on malformed input."""
    try:
        _validate_baseline_extension(report)
    except (KeyError, TypeError, IndexError, AttributeError, OverflowError, RecursionError):
        raise ValueError("baseline: malformed extension container or value") from None


def _validate_baseline_extension(report: dict[str, Any]) -> None:
    require(report.get("profile") == "full", "baseline extension requires full profile")
    baseline = closed(report.get("baseline"), {
        "schema_version", "suite_id", "run_ordinal", "started_at_utc", "completed_at_utc",
        "suite_started_at_utc", "suite_started_monotonic_ns", "started_elapsed_ms", "completed_elapsed_ms",
        "source_before", "source_after", "build_receipt", "build_receipt_sha256", "binary_use",
        "child_policy", "plan", "preflight", "anchor", "workloads", "coverage",
    }, "extension")
    public_values(baseline)
    require(baseline["schema_version"] == BASELINE_SCHEMA, "unsupported extension version")
    require(isinstance(baseline["suite_id"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", baseline["suite_id"]) is not None, "invalid suite identity")
    ordinal = baseline["run_ordinal"]
    require(type(ordinal) is int and ordinal in (1, 2, 3), "invalid run ordinal")
    validate_source(baseline["source_before"], report.get("commit"))
    exact_json(baseline["source_after"], baseline["source_before"], "source changed during measurement")
    receipt = baseline["build_receipt"]
    validate_build_receipt(receipt, baseline["source_before"])
    require(baseline["build_receipt_sha256"] == json_hash(receipt), "build receipt digest mismatch")
    require(report["binary"]["binary_hash"] == receipt["binary_sha256"] and type(report["binary"]["artifact_size_bytes"]) is int and report["binary"]["artifact_size_bytes"] == receipt["binary_size_bytes"], "report binary differs from originating build")
    provenance = "built_by_harness_from_workspace" if ordinal == 1 else "caller_supplied_prebuilt"
    require(report["binary"]["provenance"] == provenance, "prebuilt reuse provenance must not be upgraded")
    require(baseline["binary_use"] == ("built_in_run_1" if ordinal == 1 else "reused_run_1_receipt"), "incorrect build/reuse lineage")
    require(ordinal == 1 or any("source-to-binary linkage" in value for value in report["limitations"]), "prebuilt attestation caveat missing")
    exact_json(baseline["child_policy"], CHILD_POLICY, "unsafe or incomparable child environment policy")
    env = closed(report["environment"], {"captured_at_utc", "os", "os_release", "os_version", "target_triple", "architecture", "cpu", "logical_cpu_count", "ram_gb", "disk", "filesystem", "antivirus_state", "sqlite_version", "sqlite_version_source", "rustc", "python_version", "python_sqlite_version_not_store_version"}, "measured environment")
    public_values(env)
    require(env.get("target_triple") == receipt["configuration"]["target"] and env.get("rustc") == receipt["configuration"]["rustc"], "measured toolchain or target differs from build")
    require(env.get("sqlite_version") == receipt["sqlite"]["sqlite_version"] and env.get("sqlite_version_source") == "locked bundled source + this build linkage; no direct CLI runtime query", "measured SQLite provenance differs from build")
    require(finite_number(env.get("logical_cpu_count"), integer=True) and env["logical_cpu_count"] > 0 and finite_number(env.get("ram_gb")) and env["ram_gb"] > 0, "CPU/RAM environment observations required")
    for key in ("cpu", "disk", "filesystem", "antivirus_state", "architecture", "os_release", "os_version", "python_version"):
        require(isinstance(env.get(key), str) and env[key].strip() and env[key] not in {"not_recorded", "not_exposed_by_cli"}, "incomplete baseline environment")
    methods = {"windows": "windows_peak_working_set", "linux": "proc_status_rss", "darwin": "macos_ps_rss", "macos": "macos_ps_rss"}
    require(env.get("os") in methods, "unsupported measured OS")
    plan = baseline_plan(ordinal)
    plan["memory_method"] = methods[env["os"]]
    exact_json(baseline["plan"], plan, "workload, repetition, environment or budget plan mismatch")
    suite_start, start, end = (utc_value(baseline[key]) for key in ("suite_started_at_utc", "started_at_utc", "completed_at_utc"))
    require(suite_start <= start <= end, "invalid run UTC interval")
    require(finite_number(baseline["suite_started_monotonic_ns"], integer=True) and baseline["suite_started_monotonic_ns"] > 0, "invalid suite monotonic identity")
    for key in ("started_elapsed_ms", "completed_elapsed_ms"):
        require(finite_number(baseline[key]) and rounded(baseline[key]) == baseline[key], "invalid suite elapsed observation")
    require(0 <= baseline["started_elapsed_ms"] <= baseline["completed_elapsed_ms"] <= SUITE_SECONDS * 1000, "shared suite deadline exceeded")
    suffix = ".exe" if env["os"] == "windows" else ""
    all_records = list(validate_section(baseline["preflight"], "preflight", 1, 20, baseline, suffix))
    all_records += validate_section(baseline["anchor"], "anchor", 20, 200, baseline, suffix)
    workloads = baseline["workloads"]
    require(isinstance(workloads, list) and len(workloads) == 3, "three diagnostic workloads required")
    for section, name in zip(workloads, scale_order(ordinal)):
        all_records += validate_section(section, name, dict(SCALES)[name], 200, baseline, suffix)
    require([record["ordinal"] for record in all_records] == list(range(1, len(all_records) + 1)), "duplicate, missing or out-of-order invocation ordinal")
    previous_end = start
    version_hashes = set()
    for record in all_records:
        record_start, record_end = utc_value(record["started_at_utc"]), utc_value(record["completed_at_utc"])
        require(previous_end <= record_start, "overlapping or out-of-order subprocess intervals")
        previous_end = record_end
        if record["operation"].startswith("startup_"):
            version_hashes.add(record["correctness"]["version_sha256"])
    require(len(version_hashes) == 1, "startup binary versions differ")
    coverage = closed(baseline["coverage"], {"complete", "independent_catalog_oracle", "failed_observations", "trace", "limitations"}, "coverage")
    require(coverage["complete"] is True and coverage["independent_catalog_oracle"] is True and type(coverage["failed_observations"]) is int and coverage["failed_observations"] == 0, "incomplete or failed baseline coverage")
    require(coverage["trace"] == "separate-local-trial-after-primary-run-3", "trace must be separate from primary latency")
    require(isinstance(coverage["limitations"], list) and 1 <= len(coverage["limitations"]) <= 20 and all(isinstance(value, str) and value.strip() for value in coverage["limitations"]), "missing coverage limitations")
    validate_anchor_links(report)


def validate_baseline(paths: Iterable[Path]) -> dict[str, Any]:
    paths = [Path(path).expanduser().resolve() for path in paths]
    require(len(paths) == 3 and len(set(paths)) == 3, "three distinct report paths required")
    reports = [validate_report(path, "full", quiet=True) for path in paths]
    require(all("baseline" in report for report in reports), "legacy-only reports cannot qualify a baseline suite")
    require(len({sha256_file(path) for path in paths}) == 3, "duplicate reports do not form independent runs")
    reports.sort(key=lambda report: report["baseline"]["run_ordinal"])
    baselines = [report["baseline"] for report in reports]
    require([value["run_ordinal"] for value in baselines] == [1, 2, 3], "suite needs all three distinct ordinals")
    first = baselines[0]
    common = ("suite_id", "suite_started_at_utc", "suite_started_monotonic_ns", "source_before", "source_after", "build_receipt", "build_receipt_sha256", "child_policy")
    for report, value in zip(reports[1:], baselines[1:]):
        exact_json({key: value[key] for key in common}, {key: first[key] for key in common}, "suite source, build, binary, deadline or policy changed")
        exact_json(compatible_environment(report["environment"]), compatible_environment(reports[0]["environment"]), "suite host or measured environment changed")
    for previous, following in zip(baselines, baselines[1:]):
        require(previous["completed_elapsed_ms"] <= following["started_elapsed_ms"] and utc_value(previous["completed_at_utc"]) <= utc_value(following["started_at_utc"]), "runs must be independent and serial within one deadline")
    comparison: dict[str, list[float]] = {}
    corpus_inputs: dict[str, Any] = {}
    for baseline in baselines:
        for section in [baseline["anchor"], *baseline["workloads"]]:
            name = section["id"]
            inputs = [snapshot["corpus"] for snapshot in section["snapshots"]]
            if name in corpus_inputs:
                exact_json(inputs, corpus_inputs[name], "suite corpus phase inputs changed")
            corpus_inputs[name] = inputs
            for key, summary in section["summaries"].items():
                comparison.setdefault(name + "/" + key, []).append(summary["process_wall_ms"]["p50"])
    result = {"suite_id": first["suite_id"], "source_commit": reports[0]["commit"], "run_count": 3,
              "comparison": {key: median_spread(values) for key, values in sorted(comparison.items())}}
    print(f"valid {BASELINE_SCHEMA} suite: {first['suite_id']}; 3 serial runs")
    return result


def assert_summary(samples: list[float], actual: dict[str, Any], label: str) -> None:
    expected = rounded_summary(samples)
    for key, value in expected.items():
        if actual.get(key) != value:
            raise ValueError(f"{label}.summary.{key}: expected {value!r}, got {actual.get(key)!r}")


def validate_report(path: Path, expected_profile: str | None = None, *, report_data: dict[str, Any] | None = None, quiet: bool = False) -> dict[str, Any]:
    if report_data is None:
        text = path.read_text(encoding="utf-8")
        report = json.loads(text)
        if isinstance(report, dict) and "baseline" in report:
            report = strict_json(text)
    else:
        report = report_data
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
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
    if "baseline" in report:
        validate_baseline_extension(report)
    if not quiet:
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
        f"- SQLite {'build-derived version' if 'baseline' in report else 'runtime'}: `{env['sqlite_version']}` ({env['sqlite_version_source']})",
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
    if "baseline" in report:
        validate_baseline_extension(report)
        baseline = report["baseline"]
        lines.extend([
            "", "## Current-source baseline", "",
            f"- Suite/run: `{baseline['suite_id']}` / {baseline['run_ordinal']} of 3",
            f"- Measured source and checker: `{baseline['source_before']['commit']}`",
            f"- Harness SHA-256: `{baseline['source_before']['harness_sha256']}`",
            f"- Originating build receipt SHA-256: `{baseline['build_receipt_sha256']}`",
            f"- Binary use: `{baseline['binary_use']}`; linkage is not independently attested.",
            f"- UTC interval: {baseline['started_at_utc']} to {baseline['completed_at_utc']}",
            f"- Corrected timing: `{WALL_PROTOCOL}`; legacy metrics above retain `{LEGACY_PROTOCOL}`.",
            "- Anchor queries use 2,000 post-shrink Messages; scale queries use intact 2k/10k/50k corpora.",
            "- Trace is disabled for primary samples. A separate local trial follows primary run 3.",
            "- P50/P95/MAD below use persisted corrected wall times. Response bytes include the final LF.",
            "", "| Workload | Operation/class | Samples | P50 ms | P95 ms | MAD ms | P50 bytes | RSS observations |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ])
        for section in [baseline["anchor"], *baseline["workloads"]]:
            for key, summary in section["summaries"].items():
                wall = summary["process_wall_ms"]
                lines.append(f"| `{section['id']}` | `{key}` | {wall['count']} | {display(wall['p50'])} | {display(wall['p95'])} | {display(wall['mad'])} | {display(summary['stdout_bytes']['p50'])} | {summary['memory_available_count']} |")
        lines.extend(["", "### Corpus and initial-sync throughput", "", "| Workload | Initial Messages | Query Messages | Shrink Messages | Median Messages/s | Median MiB/s |", "|---|---:|---:|---:|---:|---:|"])
        for section in [baseline["anchor"], *baseline["workloads"]]:
            count = section["file_count"] * section["messages_per_file"]
            queries = count // 2 if section["id"] == "anchor" else count
            rates = section["derived"]
            lines.append(f"| `{section['id']}` | {count} | {queries} | {count // 2} | {display(rates['initial_messages_per_second']['summary']['p50'])} | {display(rates['initial_mib_per_second']['summary']['p50'])} |")
        lines.extend(["", "### Baseline limitations", ""])
        lines.extend(f"- {item}" for item in baseline["coverage"]["limitations"])
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
    run.add_argument("--baseline-run", type=int, choices=(1, 2, 3), help="opt in to one full baseline run; run 1 builds, runs 2/3 reuse its receipt")
    run.add_argument("--suite-id", help="safe identity shared by all three --baseline-run invocations")
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
    suite = sub.add_parser("validate-baseline", help="validate three complete serial baseline reports and compare run medians")
    suite.add_argument("reports", nargs=3)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "run":
            run_benchmark(args)
        elif args.command == "validate-baseline":
            comparison = validate_baseline(Path(path) for path in args.reports)
            print(json.dumps(comparison, ensure_ascii=False, indent=2, allow_nan=False))
        else:
            validate_report(Path(args.report).expanduser().resolve())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
