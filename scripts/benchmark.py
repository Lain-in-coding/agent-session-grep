#!/usr/bin/env python3
"""agent-session-grep benchmark harness (#9).

Runs discovery coverage, parse loss, and search latency benchmarks against
a local asg binary, producing a JSON report per SLI-AND-BENCHMARK-FORMAT.md.

Usage:
    python scripts/benchmark.py --asg ./target/debug/agent-session-grep
    python scripts/benchmark.py --asg ./target/debug/asg --corpus /path/to/fixtures

The benchmark is fully reproducible: same corpus + query set → same numbers.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def run_asg(asg_bin: str, data_root: str, args: list[str]) -> tuple[int, str, str]:
    """Run asg with given args, return (exit_code, stdout, stderr).

    The CLI contract puts global flags before the command name: --db and
    --output are prefixed here, subcommand flags stay in `args`. The SQLite
    store lives at ``<data_root>/catalog.db``.
    """
    db = str(Path(data_root) / "catalog.db")
    result = subprocess.run(
        [asg_bin, "--db", db, "--output", "json", *args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.returncode, result.stdout, result.stderr


def benchmark_discovery(asg_bin: str, data_root: str) -> dict:
    """Measure discovery coverage: sync --discover reports sources found."""
    start = time.perf_counter()
    code, stdout, stderr = run_asg(asg_bin, data_root, ["sync", "--discover"])
    elapsed_ms = (time.perf_counter() - start) * 1000

    if code != 0:
        return {"error": f"sync failed: {stderr}", "exit_code": code}

    try:
        frame = json.loads(stdout.strip().split("\n")[0])
        data = frame.get("data", {})
        discovery = data.get("discovery", {})
        providers = discovery.get("providers", [])

        total_found = sum(p.get("found", 0) for p in providers)
        total_complete = sum(1 for p in providers if p.get("complete", False))

        return {
            "duration_ms": round(elapsed_ms, 2),
            "sources_found": total_found,
            "providers_complete": total_complete,
            "providers_total": len(providers),
            "messages_emitted": data.get("emitted", 0),
            "messages_committed": data.get("committed", 0),
            "messages_skipped": data.get("skipped", 0),
            "generation": data.get("generation", 0),
        }
    except (json.JSONDecodeError, IndexError) as e:
        return {"error": f"parse failed: {e}", "stdout": stdout[:500]}


def benchmark_search_latency(asg_bin: str, data_root: str, queries: list[str]) -> dict:
    """Measure search p50/p95 latency over a fixed query set."""
    latencies = []
    hit_counts = []

    for query in queries:
        start = time.perf_counter()
        code, stdout, _ = run_asg(
            asg_bin, data_root, ["search", query, "--max-items", "20"]
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        if code == 0:
            latencies.append(elapsed_ms)
            try:
                frame = json.loads(stdout.strip().split("\n")[0])
                hits = frame.get("data", {}).get("hits", [])
                hit_counts.append(len(hits))
            except (json.JSONDecodeError, IndexError):
                hit_counts.append(0)
        else:
            hit_counts.append(0)

    if not latencies:
        return {"error": "no successful searches"}

    latencies.sort()
    n = len(latencies)
    p50 = latencies[n // 2] if n > 0 else 0
    p95_idx = int(n * 0.95)
    p95 = latencies[min(p95_idx, n - 1)] if n > 0 else 0

    return {
        "query_count": n,
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "min_ms": round(latencies[0], 2),
        "max_ms": round(latencies[-1], 2),
        "avg_hits": round(sum(hit_counts) / len(hit_counts), 1) if hit_counts else 0,
    }


def benchmark_index_size(data_root: str) -> dict:
    """Measure catalog/FTS index disk usage."""
    total_bytes = 0
    file_count = 0
    for root, _, files in os.walk(data_root):
        for f in files:
            path = os.path.join(root, f)
            try:
                total_bytes += os.path.getsize(path)
                file_count += 1
            except OSError:
                pass
    return {
        "data_root_bytes": total_bytes,
        "data_root_mb": round(total_bytes / (1024 * 1024), 2),
        "file_count": file_count,
    }


DEFAULT_QUERIES = [
    "error",
    "authentication",
    "database",
    "test",
    "config",
    "refactor",
    "deploy",
    "bug",
    "fix",
    "feature",
    "api",
    "migration",
]


def main():
    parser = argparse.ArgumentParser(description="agent-session-grep benchmark")
    parser.add_argument(
        "--asg", default="./target/debug/agent-session-grep", help="Path to asg binary"
    )
    parser.add_argument(
        "--data-root", default=None, help="Data root for asg (temp dir if omitted)"
    )
    parser.add_argument("--corpus", default=None, help="Path to fixture corpus for sync")
    parser.add_argument("--queries", nargs="*", default=DEFAULT_QUERIES, help="Query set")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    args = parser.parse_args()

    import tempfile

    data_root = args.data_root or tempfile.mkdtemp(prefix="asg-bench-")

    report = {
        "tool": "agent-session-grep",
        "benchmark_version": "1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "asg_binary": args.asg,
        "data_root": data_root,
    }

    # 1. Discovery + sync
    print("Running discovery benchmark...", file=sys.stderr)
    report["discovery"] = benchmark_discovery(args.asg, data_root)

    # 2. Search latency
    print(f"Running search latency benchmark ({len(args.queries)} queries)...", file=sys.stderr)
    report["search_latency"] = benchmark_search_latency(args.asg, data_root, args.queries)

    # 3. Index size
    print("Measuring index size...", file=sys.stderr)
    report["index_size"] = benchmark_index_size(data_root)

    # Output
    json_report = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(json_report, encoding="utf-8")
        print(f"Benchmark report written to {args.output}", file=sys.stderr)
    else:
        print(json_report)

    # Cleanup temp data root
    if args.data_root is None:
        import shutil

        shutil.rmtree(data_root, ignore_errors=True)


if __name__ == "__main__":
    main()
