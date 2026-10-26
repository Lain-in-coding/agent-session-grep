#!/usr/bin/env python3
"""Measure amortized semantic query latency through the long-lived MCP entry point.

One-shot CLI search pays the model load per invocation; MCP keeps the encoder
resident, so this script reports the honest per-query latency users of the
long-lived entry points actually experience. Stdlib only. Output is a small
JSON under scripts/evidence/out/ (gitignored).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

OUT = Path(__file__).resolve().parent / "out"

# Must match crates/agent-session-grep-application/src/candle_embedding.rs.
E5_SMALL_MODEL_ID = "intfloat-multilingual-e5-small@614241f6-candle-f32-meanpool-l2-qpass-v1"


def percentile(sorted_values: list[float], fraction: float) -> float:
    """Nearest-rank percentile: smallest value covering `fraction` of samples."""
    percent = round(fraction * 100)
    rank = max(1, -(-len(sorted_values) * percent // 100))
    return sorted_values[rank - 1]


def check_semantic_envelope(envelope: dict) -> None:
    """Refuse to time anything that is not a clean semantic search."""
    if envelope.get("outcome") != "success":
        raise RuntimeError(f"probe search failed: {envelope}")
    if envelope["data"].get("retrieval_mode") != "semantic" or envelope.get("warnings"):
        raise RuntimeError(
            "semantic mode did not execute: "
            f"retrieval_mode={envelope['data'].get('retrieval_mode')} "
            f"warnings={envelope.get('warnings')}"
        )


def frame(id: int, method: str, params: object) -> dict:
    return {"jsonrpc": "2.0", "id": id, "method": method, "params": params}


def run_checked(argv: list[str]) -> None:
    done = subprocess.run(argv, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(
            f"command failed ({done.returncode}): {' '.join(argv)}\n"
            f"stdout: {done.stdout}\nstderr: {done.stderr}"
        )


def verified_model_status(binary: str) -> dict:
    """Refuse to measure until a verified real embedding model is importable."""
    status = subprocess.run(
        [binary, "--robot", "model", "status"],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(status.stdout)["data"]
    if not data.get("verified") or data.get("model_kind") != "real_embedding":
        raise RuntimeError(
            f"semantic model bundle is not a verified real model (model status: {data})"
        )
    if data.get("detail", {}).get("model_id") != E5_SMALL_MODEL_ID:
        raise RuntimeError(f"unexpected model id (model status: {data})")
    return data


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "target/release/agent-session-grep.exe"
    db = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    scratch = None
    status_data = verified_model_status(binary)
    queries = [
        "ferroflux invalidate_stale",
        "FerrofluxCache epoch invalidation",
        "nebulamail drain_queue",
        "nebula retry 指数退避",
        "quartzgrid 索引 重建 一致性",
        "atlas config 备份 恢复",
        "polymorph 泛型 派生",
        "bifrost 迁移 schema 幂等",
        "warpdrive 缓存 失效 策略",
        "vertex 图 遍历 环 检测",
    ]
    if db is None:
        scratch = tempfile.TemporaryDirectory(prefix="asg-mcp-latency-")
        db = Path(scratch.name) / "latency.db"
    # Seed a few synthetic messages so semantic queries have a non-empty index.
    seed_lines = [
        json.dumps(
            {
                "type": "user",
                "uuid": f"00000000-0000-4000-8000-0000000000{i:02d}",
                "sessionId": "11111111-2222-4333-8444-555555555555",
                "timestamp": "2026-08-01T00:00:00.000Z",
                "message": {"role": "user", "content": query},
            }
        )
        for i, query in enumerate(queries)
    ]
    scratch_dir = scratch.name if scratch is not None else tempfile.gettempdir()
    fixture = Path(scratch_dir) / "asg-mcp-latency-seed.jsonl"
    fixture.write_text("\n".join(seed_lines) + "\n", encoding="utf-8")
    run_checked([binary, "--db", str(db), "--robot", "sync", str(fixture)])
    run_checked([binary, "--db", str(db), "--robot", "index", "embeddings"])

    proc = subprocess.Popen(
        [binary, "--db", str(db), "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write(
        json.dumps(
            frame(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "latency-probe", "version": "0"},
                },
            )
        )
        + "\n"
    )
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    proc.stdin.flush()
    # Drain initialize response.
    proc.stdout.readline()

    def search_once(request_id: int, query: str) -> dict:
        proc.stdin.write(
            json.dumps(
                frame(
                    request_id,
                    "tools/call",
                    {
                        "name": "search_sessions",
                        "arguments": {"query": query, "mode": "semantic", "limit": 10},
                    },
                )
            )
            + "\n"
        )
        proc.stdin.flush()
        while True:
            line = proc.stdout.readline()
            if not line:
                # EOF before a matched response means the request failed; it
                # must not become a latency datapoint.
                raise RuntimeError(f"no response for request {request_id}")
            parsed = json.loads(line)
            if parsed.get("id") == request_id:
                return parsed

    # Prove the semantic path really executes before timing anything: a
    # lexical_fallback envelope (or any warning) means the reported numbers
    # would not be semantic latency.
    probe = search_once(2, queries[0])
    check_semantic_envelope(probe["result"]["structuredContent"])

    samples = []
    for i, query in enumerate(queries):
        request_id = 2 + i
        started = time.perf_counter()
        search_once(request_id, query)
        samples.append((time.perf_counter() - started) * 1000.0)
    proc.stdin.close()
    proc.wait(timeout=60)

    samples.sort()
    p50 = percentile(samples, 0.50)
    p95 = percentile(samples, 0.95)
    OUT.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "agent-session-grep.semantic-mcp-latency/v1",
        "entry_point": "mcp",
        "model": {
            "model_id": E5_SMALL_MODEL_ID,
            "model_kind": status_data.get("model_kind"),
            "verified": status_data.get("verified"),
        },
        "query_count": len(samples),
        "p50_ms": round(p50, 1),
        "p95_ms": round(p95, 1),
        "note": "amortized per-query latency with the encoder resident in the MCP process",
    }
    (OUT / "semantic-mcp-latency.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
