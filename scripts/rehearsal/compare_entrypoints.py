#!/usr/bin/env python3
"""Five-entry-point consistency harness for the release rehearsal.

Runs one fixed synthetic search through CLI JSON, Robot, MCP, Web/HTTP, and the
TUI's headless structural projection. Web is exercised through a real loopback
``serve`` process bound to an OS-assigned port with its generated bearer token;
TUI comparison reuses the same pure Application-backed projection as the
interactive reducer and does not automate a terminal.

The report contains a closed privacy-safe field set only. Any declared entry
point that returns ``not_implemented`` makes the operation and overall verdict
fail; missing coverage can never be reported as consistent.

Usage::

    python scripts/rehearsal/compare_entrypoints.py --binary <path-to-bin>
    python scripts/rehearsal/compare_entrypoints.py --help

Exit codes: 0 all five entry points agree; 1 divergence or unimplemented entry
point; 2 usage/environment failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

#: Report schema version. Bump when the report shape changes.
REPORT_SCHEMA_VERSION = "agent-session-grep.entrypoint-consistency/v1"

#: The five entry points the release rehearsal must eventually cover.
ENTRY_POINTS = ("cli", "mcp", "robot", "web", "tui")

#: All five declared entry points are exercised by this harness.
IMPLEMENTED_ENTRY_POINTS = ENTRY_POINTS

#: The fixed query projection shared by every entry point.
CANONICAL_OPERATIONS: Dict[str, Sequence[str]] = {
    "search": ("data.hits[*].id", "page.has_more", "outcome"),
}

#: A synthetic Claude Code JSONL fixture. Two messages, both containing the
#: canonical search token ``rehearsaltoken``. Privacy-safe: no real paths,
#: ids, or identities — every value below is synthetic.
FIXTURE_LINES = [
    '{"type":"user","uuid":"a1aaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa01",'
    '"parentUuid":null,"sessionId":"b2bbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb01",'
    '"timestamp":"2026-08-15T00:00:00.000Z",'
    '"message":{"role":"user","content":"rehearsaltoken alpha question"}}',
    '{"type":"assistant","uuid":"a1aaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa02",'
    '"parentUuid":"a1aaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa01",'
    '"sessionId":"b2bbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb01",'
    '"timestamp":"2026-08-15T00:00:01.000Z",'
    '"message":{"role":"assistant","content":"rehearsaltoken alpha answer"}}',
]
#: Canonical query and page size shared by every entry point, so results are
#: comparable (a divergent default limit would produce a false divergence).
#: Page size 20 matches the CLI default limit, the MCP limit default, the Web
#: projection budget, and the TUI search page limit.
CANONICAL_QUERY = "rehearsaltoken"
CANONICAL_PAGE_SIZE = 20


class HarnessError(Exception):
    """Usage or environment failure (exit 2). Not a consistency failure."""


# ─── Helpers ─────────────────────────────────────────────────────────────────


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_fixture(dir_path: Path) -> Path:
    """Write the synthetic JSONL fixture. Returns its path."""
    fixture = dir_path / "rehearsal-fixture.jsonl"
    fixture.write_text("\n".join(FIXTURE_LINES) + "\n", encoding="utf-8")
    return fixture


# ─── CLI / Robot adapter ─────────────────────────────────────────────────────
#
# The CLI and Robot entry points share a binary: CLI emits `--output json`,
# Robot wraps the same result in the explicit `--robot` envelope. We normalize
# both to the same canonical payload by stripping the envelope.


def run_cli_json(
    binary: str, db: str, args: Sequence[str], *, robot: bool = False
) -> Dict[str, Any]:
    """Run one CLI command and parse its first JSON line."""
    mode_args = ["--robot"] if robot else ["--output", "json"]
    cmd = [binary, "--db", db, *mode_args, *args]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise HarnessError(
            f"CLI failed (exit {proc.returncode}): {' '.join(args)}\n"
            f"stderr: {proc.stderr.strip()}"
        )
    line = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
    if not line:
        raise HarnessError(f"CLI produced no JSON output for: {' '.join(args)}")
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        raise HarnessError(
            f"CLI output is not JSON ({exc}) for {' '.join(args)}:\n{line}"
        ) from exc


def strip_robot_envelope(frame: Dict[str, Any]) -> Dict[str, Any]:
    """Project a Robot v1 envelope down to the canonical payload.

    Drops transport-only fields (``schema_version``, ``request_id``,
    ``meta``, ``frame_type``) and keeps the semantic core: ``outcome``,
    ``data``, ``page``, ``warnings``.
    """
    return {
        "outcome": frame.get("outcome"),
        "data": frame.get("data"),
        "page": frame.get("page"),
        "warnings": frame.get("warnings"),
    }


def cli_run_operation(
    binary: str, db: str, op: str
) -> Dict[str, Any]:
    """Run one canonical operation through the CLI (--output json) entry point."""
    if op != "search":
        raise HarnessError(f"unknown canonical operation for CLI: {op}")
    frame = run_cli_json(
        binary,
        db,
        ["search", CANONICAL_QUERY, "--max-items", str(CANONICAL_PAGE_SIZE)],
    )
    return strip_robot_envelope(frame)


def robot_run_operation(binary: str, db: str, op: str) -> Dict[str, Any]:
    """Run the same command through the explicit ``--robot`` entry point."""
    if op != "search":
        raise HarnessError(f"unknown canonical operation for Robot: {op}")
    frame = run_cli_json(
        binary,
        db,
        ["search", CANONICAL_QUERY, "--max-items", str(CANONICAL_PAGE_SIZE)],
        robot=True,
    )
    return strip_robot_envelope(frame)


# ─── MCP adapter ─────────────────────────────────────────────────────────────


def mcp_session(
    binary: str, db: str, lines: Sequence[str]
) -> List[Dict[str, Any]]:
    """Run one MCP stdio session and return all parsed JSON-RPC frames."""
    proc = subprocess.run(
        [binary, "--db", db, "mcp"],
        input="\n".join(lines) + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise HarnessError(
            f"MCP session exited {proc.returncode}\nstderr: {proc.stderr.strip()}"
        )
    frames: List[Dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            frames.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise HarnessError(f"MCP stdout not pure JSON-RPC: {exc}\n{line}") from exc
    return frames


def mcp_frame_by_id(frames: Sequence[Dict[str, Any]], rpc_id: int) -> Dict[str, Any]:
    for frame in frames:
        if frame.get("id") == rpc_id:
            return frame
    raise HarnessError(f"no MCP response frame with id {rpc_id}")


INIT_LINES = [
    json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "consistency-harness", "version": "0"},
            },
        }
    ),
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
]


def mcp_structured_content(frame: Dict[str, Any]) -> Dict[str, Any]:
    """Pull structuredContent out of a tools/call result frame."""
    result = frame.get("result", {})
    content = result.get("structuredContent")
    if not isinstance(content, dict):
        raise HarnessError(
            f"MCP result has no structuredContent: {json.dumps(frame)[:200]}"
        )
    return content


def mcp_run_operation(
    binary: str, db: str, op: str
) -> Dict[str, Any]:
    """Run one canonical operation through the MCP JSON-RPC entry point."""
    if op != "search":
        raise HarnessError(f"unknown canonical operation for MCP: {op}")
    tool_name = "search_sessions"
    arguments = {"query": CANONICAL_QUERY, "max_items": CANONICAL_PAGE_SIZE}
    call = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
    )
    frames = mcp_session(binary, db, [*INIT_LINES, call])
    resp = mcp_frame_by_id(frames, 2)
    return mcp_structured_content(resp)


# ─── TUI adapter ─────────────────────────────────────────────────────────────


def tui_run_operation(binary: str, db: str, op: str) -> Dict[str, Any]:
    """Run the TUI's headless Application-backed projection."""
    if op != "search":
        raise HarnessError(f"unknown canonical operation for TUI: {op}")
    return run_cli_json(binary, db, ["tui", "--snapshot-json", CANONICAL_QUERY])


# ─── Web / HTTP adapter ──────────────────────────────────────────────────────


def _serve_url(binary: str, db: str) -> Tuple[subprocess.Popen[str], str]:
    """Start serve on an ephemeral loopback port and discover its token/address."""
    proc: subprocess.Popen[str] = subprocess.Popen(
        [binary, "--db", db, "serve", "--port", "0"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert proc.stderr is not None
    lines: queue.Queue[str] = queue.Queue()

    def collect_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            lines.put(line.rstrip())

    threading.Thread(target=collect_stderr, daemon=True).start()
    deadline = time.monotonic() + 10
    address = token = None
    while time.monotonic() < deadline:
        try:
            line = lines.get(timeout=0.1)
        except queue.Empty:
            if proc.poll() is not None:
                break
            continue
        # Current serve prints one ready line: `asg serve: open http://<addr>/?token=<token>`.
        if line.startswith("asg serve: open http://") and address is None:
            ready = line.removeprefix("asg serve: open ")
            parsed = urllib.parse.urlsplit(ready)
            address = f"{parsed.scheme}://{parsed.netloc}"
            token = urllib.parse.parse_qs(parsed.query).get("token", [None])[0]
        if address and token:
            return proc, f"{address}?token={urllib.parse.quote(token)}"
    stderr = "\\n".join(list(lines.queue))
    proc.terminate()
    proc.wait(timeout=5)
    raise HarnessError(f"serve did not become ready: {stderr}")


def web_get(base_url: str, path: str, token: str) -> Dict[str, Any]:
    request = urllib.request.Request(
        f"{base_url}{path}",
        headers={"Authorization": f"Bearer {token}", "Host": "127.0.0.1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status != 200:
                raise HarnessError(f"Web GET {path} returned HTTP {response.status}")
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise HarnessError(f"Web GET {path} failed: {exc}") from exc


def web_run_operation(binary: str, db: str, op: str) -> Dict[str, Any]:
    """Exercise the real loopback Web API and return its shared projection."""
    if op != "search":
        raise HarnessError(f"unknown canonical operation for Web: {op}")
    proc, ready_url = _serve_url(binary, db)
    try:
        parsed = urllib.parse.urlsplit(ready_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        token = urllib.parse.parse_qs(parsed.query)["token"][0]
        payload = web_get(
            base_url,
            f"/api/projection/search?q={urllib.parse.quote(CANONICAL_QUERY)}",
            token,
        )
        return payload
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# ─── Canonical field extraction ──────────────────────────────────────────────


def get_path(obj: Any, dotted: str) -> Any:
    """Resolve a dotted path. ``[*]`` collects array elements into a list.

    ``data.hits[*].id`` → ``[item.get("id") for item in data["hits"]]``.
    Returns ``None`` when any segment is absent.
    """
    parts = dotted.split(".")
    cur = obj
    i = 0
    while i < len(parts):
        part = parts[i]
        if part.endswith("[*]"):
            key = part[:-3]
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
            if not isinstance(cur, list):
                return None
            rest = ".".join(parts[i + 1:])
            if not rest:
                return cur
            return [get_path(item, rest) for item in cur]
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        i += 1
    return cur


def canonical_view(
    payload: Dict[str, Any], op: str
) -> Dict[str, Any]:
    """Project a normalized payload down to the closed canonical field set."""
    fields = CANONICAL_OPERATIONS[op]
    view: Dict[str, Any] = {}
    for path in fields:
        value = get_path(payload, path)
        # Normalize None to a stable sentinel so absence is comparable.
        view[path] = value if value is not None else "__absent__"
    return view


def compare_canonical(
    op: str, results: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Compare canonical views across all entry points for one op.

    A ``not_implemented`` adapter fails the operation outright: release
    consistency never treats missing coverage as a pass.
    """
    views: Dict[str, Dict[str, Any]] = {}
    skipped: List[Dict[str, Any]] = []
    aliases: List[Dict[str, Any]] = []
    unimplemented: List[Dict[str, Any]] = []
    for entry_point, payload in results.items():
        if isinstance(payload, dict) and payload.get("status") == "not_implemented":
            unimplemented.append(payload)
            continue
        if isinstance(payload, dict) and payload.get("status") == "alias":
            aliases.append({"entry_point": entry_point, **payload})
            continue
        views[entry_point] = canonical_view(payload, op)
    if unimplemented:
        return {
            "operation": op,
            "verdict": "not_implemented",
            "compared": list(views.keys()),
            "skipped": [],
            "aliases": aliases,
            "unimplemented": unimplemented,
            "divergences": [],
        }
    if not views:
        return {
            "operation": op,
            "verdict": "no_implemented_entry_points",
            "compared": [],
            "skipped": skipped,
            "aliases": aliases,
            "unimplemented": [],
            "divergences": [],
        }
    reference_ep = next(iter(views))
    reference = views[reference_ep]
    divergences: List[Dict[str, Any]] = []
    for entry_point, view in views.items():
        if entry_point == reference_ep:
            continue
        for field, value in reference.items():
            other = view.get(field)
            if value != other:
                divergences.append(
                    {
                        "field": field,
                        f"{reference_ep}": _redact_value(field, value),
                        entry_point: _redact_value(field, other),
                    }
                )
    verdict = "consistent" if not divergences else "divergent"
    return {
        "operation": op,
        "verdict": verdict,
        "compared": list(views.keys()),
        "skipped": skipped,
        "aliases": aliases,
        "unimplemented": [],
        "divergences": divergences,
    }


def _redact_value(field: str, value: Any) -> Any:
    """Privacy guard: ids are opaque wire tokens (``msg_v1_…``/``ses_v1_…``)

    and already free of personal data, but counts and booleans are safe to
    carry verbatim. We never carry message text — the canonical field set
    only includes ids/counts/booleans, never text.
    """
    return value


# ─── Orchestration ───────────────────────────────────────────────────────────


def ingest_fixture(binary: str, db: str, fixture: Path) -> None:
    """Ingest the synthetic fixture so every entry point queries the same data."""
    proc = subprocess.run(
        [binary, "--db", db, "ingest", str(fixture)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise HarnessError(
            f"ingest failed (exit {proc.returncode})\nstderr: {proc.stderr.strip()}"
        )


def run_all(
    binary: str, workdir: Path
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Run every canonical operation through every entry point.

    Returns (report, per-operation comparisons)."""
    db_path = workdir / "consistency.db"
    db = str(db_path)
    fixture = write_fixture(workdir)
    ingest_fixture(binary, db, fixture)

    per_op: List[Dict[str, Any]] = []
    for op in CANONICAL_OPERATIONS:
        results: Dict[str, Dict[str, Any]] = {
            "cli": cli_run_operation(binary, db, op),
            "mcp": mcp_run_operation(binary, db, op),
            "robot": robot_run_operation(binary, db, op),
            "web": web_run_operation(binary, db, op),
            "tui": tui_run_operation(binary, db, op),
        }
        per_op.append(compare_canonical(op, results))
    report = build_report(binary, per_op)
    return report, per_op


def build_report(binary: str, per_op: List[Dict[str, Any]]) -> Dict[str, Any]:
    overall = "consistent"
    for comparison in per_op:
        if comparison["verdict"] != "consistent":
            overall = "divergent"
            break
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "binary_sha256": sha256_file(Path(binary)) if Path(binary).exists() else None,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
        },
        "entry_points": {
            "implemented": list(IMPLEMENTED_ENTRY_POINTS),
            "declared": list(ENTRY_POINTS),
            "pending": [ep for ep in ENTRY_POINTS if ep not in IMPLEMENTED_ENTRY_POINTS],
        },
        "operations": per_op,
        "overall_verdict": overall,
        "privacy": {
            "message_text": "never_compared",
            "absolute_source_paths": "never_emitted",
            "provider_native_ids": "never_emitted",
            "fingerprints": "never_emitted",
            "usernames": "never_emitted",
            "hostnames": "never_emitted",
        },
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="compare_entrypoints.py",
        description="Five-entry-point consistency harness for the release rehearsal.",
    )
    parser.add_argument(
        "--binary",
        default=os.environ.get("ASG_BINARY", ""),
        help="Path to the agent-session-grep binary "
        "(default: $ASG_BINARY).",
    )
    parser.add_argument(
        "--workdir",
        default="",
        help="Working directory for the fixture db (default: tempdir).",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Write the report JSON to this path (default: stdout only).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit only the report JSON to stdout (no human summary).",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    if not args.binary:
        print("error: --binary is required (or set ASG_BINARY)", file=sys.stderr)
        return 2
    binary = os.path.abspath(args.binary)
    if not Path(binary).is_file():
        print(f"error: binary not found: {binary}", file=sys.stderr)
        return 2

    if args.workdir:
        workdir = Path(args.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        cleanup = False
    else:
        workdir = Path(tempfile.mkdtemp(prefix="asg-consistency-"))
        cleanup = True

    try:
        report, _ = run_all(binary, workdir)
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)
        return 2

    report_text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(report_text, encoding="utf-8")
    if args.json:
        print(report_text)
    else:
        print(report_text)
        print(
            f"\n[summary] overall_verdict={report['overall_verdict']} "
            f"compared_entry_points={report['entry_points']['implemented']} "
            f"pending={report['entry_points']['pending']}",
            file=sys.stderr,
        )
    if cleanup:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0 if report["overall_verdict"] == "consistent" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
