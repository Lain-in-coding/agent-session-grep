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


def frame(id: int, method: str, params: object) -> dict:
    return {"jsonrpc": "2.0", "id": id, "method": method, "params": params}


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "target/release/agent-session-grep.exe"
    db = Path(sys.argv[2]) if len(sys.argv) > 2 else None
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
    fixture = Path(scratch.name) / "seed.jsonl"
    fixture.write_text("\n".join(seed_lines) + "\n", encoding="utf-8")
    subprocess.run(
        [binary, "--db", str(db), "--robot", "sync", str(fixture)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [binary, "--db", str(db), "--robot", "index", "embeddings"],
        check=True,
        capture_output=True,
    )

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
    samples = []
    for i, query in enumerate(queries):
        request_id = 2 + i
        started = time.perf_counter()
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
                break
            parsed = json.loads(line)
            if parsed.get("id") == request_id:
                break
        samples.append((time.perf_counter() - started) * 1000.0)
    proc.stdin.close()
    proc.wait(timeout=60)

    samples.sort()
    p50 = samples[len(samples) // 2]
    p95 = samples[int(len(samples) * 0.95) - 1]
    OUT.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "agent-session-grep.semantic-mcp-latency/v1",
        "entry_point": "mcp",
        "model": "intfloat-multilingual-e5-small@614241f6-candle-f32-meanpool-l2-qpass-v1",
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
