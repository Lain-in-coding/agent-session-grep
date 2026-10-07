#!/usr/bin/env python3
"""Open-source gate benchmark for agent-session-grep.

Adds the metrics the public benchmark needs beyond the core latency harness:
lexical recall on a synthetic labeled corpus, parse-loss accounting,
discovery-coverage scaffolding, resume/handoff success counters, and a single
gate evidence manifest that records each metric's threshold, pass/fail, and
the environment block. Metrics whose feature has not landed yet are recorded
explicitly with state "not_applicable" — never silently skipped.

Uses only the Python standard library. Helpers are reused from
core_beta_benchmark.py so the two harnesses stay consistent.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Reuse the frozen helpers from the core harness so both reports stay
# byte-compatible in their statistical projections.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core_beta_benchmark import (  # noqa: E402
    cli,
    command_text,
    parse_frame,
    rounded_summary,
    run_process,
    sha256_file,
    tree_hash,
)

GATE_SCHEMA_VERSION = "agent-session-grep.open-source-gate/v1"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "gate"
LABELS_PATH = FIXTURE_DIR / "labels.json"

# Metric names that carry a gate threshold. The full manifest also records
# informational metrics (latency p50/p95, index size) without a threshold.
GATE_THRESHOLDS = {
    "lexical_recall_at_10": 0.95,
    "parse_loss_ratio": 0.05,
    "discovery_coverage": 0.95,
    "resume_handoff_success": 1.0,
}

# Measured but deliberately un-thresholded. These are reported so the numbers
# are public and comparable, without letting them gate a release: the shipped
# vectorizer is a bigram hash (fuzzy lexical, not semantic), so a good score
# here would not justify promoting semantic retrieval. Each entry must carry a
# reason explaining why it has no threshold.
INFORMATIONAL_METRICS = {
    "semantic_recall_at_10",
    "hybrid_recall_at_10",
}

# Where each fixture group is planted for the discovery measurement, keyed by
# the fixture subdirectory name. The suffix must match `provider_data_root` in
# the CLI — if the two drift, discovery coverage would silently read 0.
DISCOVERY_ROOTS = {
    "claude": ("claude-code", Path(".claude") / "projects"),
    "codex": ("codex", Path(".codex") / "sessions"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_labels() -> dict[str, Any]:
    return json.loads(LABELS_PATH.read_text(encoding="utf-8"))


def corpus_files() -> list[Path]:
    files = sorted(FIXTURE_DIR.rglob("*.jsonl"))
    # labels.json is a manifest, not a transcript source.
    return [p for p in files if p.name != "labels.json"]


def resolve_binary(workspace: Path, args: argparse.Namespace) -> Path:
    if args.binary:
        binary = Path(args.binary).expanduser().resolve()
    else:
        build = subprocess.run(
            [args.cargo, "build", "--locked", "--release", "-p", "agent-session-grep-cli"],
            cwd=workspace,
            check=False,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            hint = (
                "\ncargo build failed. If a running agent-session-grep (e.g. an MCP"
                "\nserver) holds target/release/agent-session-grep.exe locked on"
                "\nWindows, build into an isolated target dir or pass --binary with"
                "\na prebuilt release binary."
            )
            raise RuntimeError(
                f"cargo build --locked --release failed (exit {build.returncode}):"
                f"\n{build.stdout.strip()}\n{build.stderr.strip()}{hint}"
            )
        name = "agent-session-grep.exe" if platform.system().lower() == "windows" else "agent-session-grep"
        binary = workspace / "target" / "release" / name
    if not binary.is_file():
        raise FileNotFoundError(f"release CLI binary not found: {binary}")
    return binary


def recall_at_10(
    binary: Path,
    workspace: Path,
    db: Path,
    labels: dict[str, Any],
    mode: str,
) -> tuple[float, list[dict[str, Any]], list[dict[str, Any]]]:
    """Run every labeled query in one retrieval mode and score id recall @10.

    Returns (mean_recall, per_query_detail, raw_search_samples). Search hits
    are message-level; recall is computed against expected_message_ids. A
    response whose effective retrieval_mode differs from the requested one
    (i.e. it fell back) is recorded per query so a fallback can never be
    reported as a semantic measurement.
    """
    per_query: list[dict[str, Any]] = []
    search_samples: list[dict[str, Any]] = []
    recalls: list[float] = []
    for entry in labels["queries"]:
        extra = [] if mode == "lexical" else ["--mode", mode]
        result = cli(
            binary, workspace, db, "search", entry["query"], "--max-items", "10", *extra
        )
        search_samples.append(result)
        frame = result["frame"]
        hits = frame["data"].get("hits", [])
        hit_ids = {hit.get("id") for hit in hits}
        expected = set(entry["expected_message_ids"])
        found = expected & hit_ids
        recall = len(found) / len(expected) if expected else 1.0
        recalls.append(recall)
        per_query.append(
            {
                "query_id": entry["id"],
                "query": entry["query"],
                "requested_mode": mode,
                "effective_mode": frame.get("retrieval_mode", "not_recorded"),
                "expected_count": len(expected),
                "found_count": len(found),
                "recall_at_10": round(recall, 6),
                "missing_ids": sorted(expected - hit_ids),
            }
        )
    mean_recall = round(sum(recalls) / len(recalls), 6) if recalls else 1.0
    return mean_recall, per_query, search_samples


def lexical_recall_at_10(
    binary: Path,
    workspace: Path,
    db: Path,
    labels: dict[str, Any],
) -> tuple[float, list[dict[str, Any]], list[dict[str, Any]]]:
    """Lexical recall @10 (the gate threshold metric)."""
    return recall_at_10(binary, workspace, db, labels, "lexical")


def discovery_coverage(
    binary: Path,
    workspace: Path,
    scratch: Path,
    fixture_files: list[Path],
) -> dict[str, Any]:
    """Measure what fraction of planted sources `sync --discover` finds.

    Each fixture is planted under the data root of the provider that wrote it
    (`claude/` → `~/.claude/projects`, `codex/` → `~/.codex/sessions`), then
    discovery runs against a fake HOME containing only those copies. Real user
    transcripts are never read: the gate corpus is synthetic and HOME/USERPROFILE
    are redirected for this one call.
    """
    fake_home = scratch / "discovery-home"
    planted_by_provider: dict[str, int] = {}
    for source in fixture_files:
        group = source.parent.name
        if group not in DISCOVERY_ROOTS:
            raise RuntimeError(
                f"fixture {source.name} lives in unmapped group {group!r}; "
                f"add it to DISCOVERY_ROOTS so discovery coverage stays honest"
            )
        provider_id, root_suffix = DISCOVERY_ROOTS[group]
        planted_root = fake_home / root_suffix
        planted_root.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, planted_root / source.name)
        planted_by_provider[provider_id] = planted_by_provider.get(provider_id, 0) + 1

    env = dict(os.environ)
    env["HOME"] = str(fake_home)
    env["USERPROFILE"] = str(fake_home)
    db = scratch / "discovery.db"
    sample = run_process(
        [str(binary), "--db", str(db), "--output", "json", "sync", "--discover"],
        workspace,
        env=env,
    )
    data = parse_frame(sample["stdout"])["data"]
    # `sync --discover` reports per-provider counts, never absolute paths.
    discovery = data.get("discovery", {})
    by_id = {p.get("id"): p for p in discovery.get("providers", [])}

    planted = sum(planted_by_provider.values())
    found = 0
    detail: list[dict[str, Any]] = []
    all_complete = True
    for provider_id, expected in sorted(planted_by_provider.items()):
        entry = by_id.get(provider_id, {})
        provider_found = int(entry.get("found", 0))
        complete = bool(entry.get("complete", False))
        found += min(provider_found, expected)
        all_complete = all_complete and complete
        detail.append(
            {
                "provider_id": provider_id,
                "planted": expected,
                "found": provider_found,
                "complete": complete,
            }
        )

    return {
        "coverage": round(found / planted, 6) if planted else 1.0,
        "planted": planted,
        "found": found,
        "planted_providers_complete": all_complete,
        "messages": data.get("messages"),
        "emitted": data.get("emitted"),
        "per_provider": detail,
        "sample": sample,
    }


def resolve_canonical_session_ids(
    binary: Path,
    workspace: Path,
    db: Path,
) -> dict[str, str]:
    """Map each provider-native session id to its canonical `ses_v1_*` wire id.

    Canonical session identity is a digest over (provider, installation
    namespace, native id), so it depends on where the corpus lives on disk and
    cannot be pinned in the labels file. The mapping is read back from the store
    via `get-session-resume`, which is the same contract a user would use.
    """
    listing = cli(binary, workspace, db, "list", "1000")
    page = listing["frame"].get("page", {})
    if page.get("has_more"):
        raise RuntimeError("gate store holds more entities than one page; raise the list limit")
    session_ids = [
        entry["id"]
        for entry in listing["frame"]["data"]["entries"]
        if str(entry["id"]).startswith("ses_v1_")
    ]
    mapping: dict[str, str] = {}
    for canonical in session_ids:
        data = cli(binary, workspace, db, "get-session-resume", canonical)["frame"]["data"]
        native = data.get("provider_session_id")
        if not native:
            continue
        if native in mapping:
            raise RuntimeError(
                f"provider session id {native!r} maps to two canonical sessions; "
                f"the gate corpus must keep native ids unique per provider"
            )
        mapping[native] = canonical
    return mapping


def resume_handoff_success(
    binary: Path,
    workspace: Path,
    db: Path,
    labels: dict[str, Any],
) -> dict[str, Any]:
    """Count sessions where resume preview and handoff both produce a result.

    Resume runs as dry-run only — the gate never spawns a provider process, so
    a "success" means the CLI produced a concrete, inspectable command, not that
    a provider was launched. A handoff counts when the pack carries at least one
    verbatim evidence span.

    The denominator is the labeled ground truth: every provider-native session
    id named in the labels must resolve to a canonical session that previews a
    resume command.
    """
    expected_native = sorted(
        {sid for entry in labels["queries"] for sid in entry["expected_provider_session_ids"]}
    )
    if not expected_native:
        raise RuntimeError("labels name no provider session ids; resume cannot be measured")
    resolved = resolve_canonical_session_ids(binary, workspace, db)

    detail: list[dict[str, Any]] = []
    resume_samples: list[dict[str, Any]] = []
    resume_ok = 0
    for native in expected_native:
        canonical = resolved.get(native)
        if canonical is None:
            # A labeled session whose resume metadata never landed is a failure,
            # not an excuse to shrink the denominator.
            detail.append(
                {
                    "provider_session_id": native,
                    "session_id": None,
                    "provider_id": None,
                    "resume_available": False,
                    "resume_command_present": False,
                    "executed": False,
                    "unavailable_reason": "no canonical session claims this provider session id",
                }
            )
            continue
        result = cli(binary, workspace, db, "resume", canonical)
        resume_samples.append(result)
        data = result["frame"]["data"]
        available = bool(data.get("available"))
        has_command = bool(data.get("command"))
        executed = bool(data.get("executed"))
        if available and has_command and not executed:
            resume_ok += 1
        detail.append(
            {
                "provider_session_id": native,
                "session_id": canonical,
                "provider_id": data.get("provider_id"),
                "resume_available": available,
                "resume_command_present": has_command,
                "executed": executed,
                "unavailable_reason": data.get("unavailable_reason"),
            }
        )

    handoff_ok = 0
    handoff_samples: list[dict[str, Any]] = []
    handoff_detail: list[dict[str, Any]] = []
    for entry in labels["queries"]:
        result = cli(binary, workspace, db, "handoff", entry["query"])
        handoff_samples.append(result)
        pack = result["frame"]["data"]
        evidence = pack.get("evidence", [])
        if evidence:
            handoff_ok += 1
        handoff_detail.append(
            {
                "query_id": entry["id"],
                "evidence_count": len(evidence),
                "matched_sessions": len(pack.get("matched_sessions", [])),
                "confidence": pack.get("confidence", {}).get("overall"),
                "truncated": pack.get("truncation", {}).get("truncated"),
            }
        )

    total = len(expected_native) + len(labels["queries"])
    succeeded = resume_ok + handoff_ok
    ratio = round(succeeded / total, 6) if total else 1.0
    return {
        "ratio": ratio,
        "attempted": total,
        "succeeded": succeeded,
        "resume_sessions": len(expected_native),
        "resume_previews_ok": resume_ok,
        "handoff_queries": len(labels["queries"]),
        "handoff_packs_ok": handoff_ok,
        "resume_detail": detail,
        "handoff_detail": handoff_detail,
        "resume_samples": resume_samples,
        "handoff_samples": handoff_samples,
    }


def parse_loss_from_sync(sync_frames: list[dict[str, Any]]) -> dict[str, Any]:
    emitted = sum(int(f["data"].get("emitted", 0)) for f in sync_frames)
    skipped = sum(int(f["data"].get("skipped", 0)) for f in sync_frames)
    total = emitted + skipped
    ratio = round(skipped / total, 6) if total else 0.0
    return {"emitted": emitted, "skipped": skipped, "parse_loss_ratio": ratio}


def latency_p50_p95(samples: list[dict[str, Any]]) -> dict[str, float]:
    durations = [float(s["duration_ms"]) for s in samples]
    summary = rounded_summary(durations)
    return {"p50": summary["p50"], "p95": summary["p95"], "count": summary["count"]}


def metric_entry(
    name: str,
    unit: str,
    value: Any,
    threshold: float | None,
    pass_flag: bool | None,
    state: str = "measured",
    reason: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": name,
        "unit": unit,
        "state": state,
        "value": value,
        "threshold": threshold,
        "pass": pass_flag,
    }
    if reason:
        entry["reason"] = reason
    return entry


def run_gate(args: argparse.Namespace) -> Path:
    workspace = Path(args.workspace).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    commit = command_text(["git", "rev-parse", "HEAD"], workspace) or "not_recorded"
    binary = resolve_binary(workspace, args)
    labels = load_labels()
    fixture_files = corpus_files()
    if not fixture_files:
        raise RuntimeError(f"no labeled fixture sources found under {FIXTURE_DIR}")
    fixture_hash = tree_hash(fixture_files, FIXTURE_DIR)

    with tempfile.TemporaryDirectory(prefix="agent-session-grep-gate-") as temp_name:
        scratch = Path(temp_name)
        db = scratch / "gate.db"

        # Sync the labeled corpus by explicit path. discovery_coverage below
        # re-runs the same corpus through `sync --discover` against a redirected
        # HOME so the two paths are measured independently.
        sync_frames: list[dict[str, Any]] = []
        sync_samples: list[dict[str, Any]] = []
        for _ in range(max(1, args.sync_reps)):
            result = cli(binary, workspace, db, "sync", *(str(p) for p in fixture_files))
            sync_frames.append(result["frame"])
            sync_samples.append(result)

        loss = parse_loss_from_sync(sync_frames)

        mean_recall, per_query, search_samples = lexical_recall_at_10(binary, workspace, db, labels)

        # Semantic/hybrid recall (#3). The vector index must be built first;
        # without it every query falls back to lexical and the numbers would
        # describe lexical retrieval under a semantic label.
        embeddings_result = cli(binary, workspace, db, "index", "embeddings")
        embeddings_frame = embeddings_result["frame"]["data"]
        semantic_recall, semantic_per_query, semantic_samples = recall_at_10(
            binary, workspace, db, labels, "semantic"
        )
        hybrid_recall, hybrid_per_query, hybrid_samples = recall_at_10(
            binary, workspace, db, labels, "hybrid"
        )
        semantic_fell_back = any(
            q["effective_mode"] != q["requested_mode"]
            for q in semantic_per_query + hybrid_per_query
        )

        # Auto-discovery coverage: plants the same synthetic corpus under a
        # redirected HOME and checks `sync --discover` finds every source.
        discovery = discovery_coverage(binary, workspace, scratch, fixture_files)

        # Resume + handoff: both dry-run only, no provider process is spawned.
        resume_handoff = resume_handoff_success(binary, workspace, db, labels)

        # Latency for show/get against known wire ids from the labels.
        first_expected = labels["queries"][0]["expected_message_ids"][0]
        show_samples = [
            cli(binary, workspace, db, "show", first_expected) for _ in range(args.latency_reps)
        ]
        get_samples = [
            cli(binary, workspace, db, "get", first_expected) for _ in range(args.latency_reps)
        ]

        # Index size ratio from the synced store.
        storage_files = list(scratch.glob("gate.db*"))
        store_bytes = sum(p.stat().st_size for p in storage_files if p.is_file())
        source_bytes = sum(p.stat().st_size for p in fixture_files)
        index_size_ratio = round(store_bytes / source_bytes, 6) if source_bytes else None

    # Gate metrics. Every threshold metric is measured; nothing is silently
    # skipped, and a metric may only be state "not_applicable" when the feature
    # it measures genuinely does not exist.
    metrics: list[dict[str, Any]] = [
        metric_entry(
            "lexical_recall_at_10",
            "ratio",
            mean_recall,
            GATE_THRESHOLDS["lexical_recall_at_10"],
            mean_recall >= GATE_THRESHOLDS["lexical_recall_at_10"],
        ),
        metric_entry(
            "parse_loss_ratio",
            "ratio",
            loss["parse_loss_ratio"],
            GATE_THRESHOLDS["parse_loss_ratio"],
            loss["parse_loss_ratio"] <= GATE_THRESHOLDS["parse_loss_ratio"],
        ),
        # semantic/hybrid recall are measured but carry no gate threshold: the
        # shipped vectorizer is a bigram hash (fuzzy lexical, not semantic), so
        # a passing number here would not license promoting semantic retrieval.
        # A real embedding model is what makes a threshold meaningful.
        metric_entry(
            "semantic_recall_at_10",
            "ratio",
            semantic_recall,
            None,
            None,
            reason=(
                "measured with the bigram-hash vectorizer (fuzzy lexical similarity, "
                "not semantic); no gate threshold until a real embedding model lands"
            ),
        ),
        metric_entry(
            "hybrid_recall_at_10",
            "ratio",
            hybrid_recall,
            None,
            None,
            reason=(
                "RRF fusion of lexical + bigram-hash vectors; no gate threshold until "
                "a real embedding model lands"
            ),
        ),
        metric_entry(
            "discovery_coverage",
            "ratio",
            discovery["coverage"],
            GATE_THRESHOLDS["discovery_coverage"],
            discovery["coverage"] >= GATE_THRESHOLDS["discovery_coverage"],
        ),
        metric_entry(
            "resume_handoff_success",
            "ratio",
            resume_handoff["ratio"],
            GATE_THRESHOLDS["resume_handoff_success"],
            resume_handoff["ratio"] >= GATE_THRESHOLDS["resume_handoff_success"],
        ),
    ]

    applicable = [
        m for m in metrics if m["name"] in GATE_THRESHOLDS and m["state"] == "measured"
    ]
    failures = [m["name"] for m in applicable if m["pass"] is False]
    deferred = [m["name"] for m in metrics if m["state"] == "not_applicable"]
    gate_pass = not failures

    manifest: dict[str, Any] = {
        "schema_version": GATE_SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "commit": commit,
        "environment": {
            "os": platform.system().lower(),
            "arch": platform.machine() or "not_recorded",
            "build": "release",
            "commit": commit,
            "provider_fixture_set_id": labels.get("fixture_set_id", "not_recorded"),
            "python_version": platform.python_version(),
        },
        "corpus": {
            "kind": "deterministic_synthetic_labeled",
            "contains_real_transcripts": False,
            "fixture_set_id": labels.get("fixture_set_id", "not_recorded"),
            "providers": labels.get("providers", []),
            "file_count": len(fixture_files),
            "fixture_hash": fixture_hash,
            "hash_algorithm": "sha256",
        },
        "binary": {
            "hash_algorithm": "sha256",
            "binary_hash": sha256_file(binary),
        },
        "metrics": metrics,
        "recall_detail": per_query,
        "retrieval_modes": {
            "vectorizer": {
                "model_id": embeddings_frame.get("model_id"),
                "dimension": embeddings_frame.get("dimension"),
                "license": embeddings_frame.get("license"),
                "file_hash": embeddings_frame.get("file_hash"),
                "kind": "bigram_hash_not_semantic",
            },
            "vectors_indexed": embeddings_frame.get("indexed"),
            "vectors_skipped": embeddings_frame.get("skipped"),
            "any_request_fell_back": semantic_fell_back,
            "semantic_detail": semantic_per_query,
            "hybrid_detail": hybrid_per_query,
        },
        "parse_loss_detail": loss,
        "discovery_detail": {
            "mechanism": "sync --discover against a redirected HOME holding synthetic fixture copies",
            "reads_real_transcripts": False,
            "planted": discovery["planted"],
            "found": discovery["found"],
            "planted_providers_complete": discovery["planted_providers_complete"],
            "messages": discovery["messages"],
            "per_provider": discovery["per_provider"],
        },
        "resume_handoff_detail": {
            "mechanism": "resume dry-run (no provider process spawned) + handoff pack evidence check",
            "attempted": resume_handoff["attempted"],
            "succeeded": resume_handoff["succeeded"],
            "resume_sessions": resume_handoff["resume_sessions"],
            "resume_previews_ok": resume_handoff["resume_previews_ok"],
            "handoff_queries": resume_handoff["handoff_queries"],
            "handoff_packs_ok": resume_handoff["handoff_packs_ok"],
            "resume_detail": resume_handoff["resume_detail"],
            "handoff_detail": resume_handoff["handoff_detail"],
        },
        "latency_p50_p95_ms": {
            "search": latency_p50_p95(search_samples),
            "search_semantic": latency_p50_p95(semantic_samples),
            "search_hybrid": latency_p50_p95(hybrid_samples),
            "show": latency_p50_p95(show_samples),
            "get": latency_p50_p95(get_samples),
            "initial_sync": latency_p50_p95(sync_samples),
            "discovery_sync": latency_p50_p95([discovery["sample"]]),
            "resume_preview": latency_p50_p95(resume_handoff["resume_samples"]),
            "handoff": latency_p50_p95(resume_handoff["handoff_samples"]),
        },
        "index_size": {
            "store_bytes_including_sidecars": store_bytes,
            "source_bytes": source_bytes,
            "index_size_ratio": index_size_ratio,
        },
        "gate": {
            "pass": gate_pass,
            "failures": failures,
            "deferred": deferred,
        },
    }

    manifest_path = output_dir / f"gate-manifest-{args.profile}.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    validate_manifest(manifest_path)
    print(manifest_path)
    return manifest_path


def validate_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != GATE_SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {manifest.get('schema_version')!r}")
    commit = manifest.get("commit", "")
    if not isinstance(commit, str) or len(commit) != 40:
        raise ValueError("commit must be a full Git SHA")
    if manifest.get("corpus", {}).get("contains_real_transcripts") is not False:
        raise ValueError("corpus.contains_real_transcripts must be false")
    metrics = manifest.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        raise ValueError("metrics must be a non-empty list")
    expected_names = set(GATE_THRESHOLDS) | INFORMATIONAL_METRICS
    actual_names = {m.get("name") for m in metrics}
    if actual_names != expected_names:
        raise ValueError(f"metric names {sorted(actual_names)} do not match gate schema {sorted(expected_names)}")
    for m in metrics:
        name = m.get("name")
        threshold = m.get("threshold")
        state = m.get("state")
        if name in INFORMATIONAL_METRICS:
            # Informational: no threshold, no pass verdict, and a stated reason
            # so a reader cannot mistake it for a gate metric.
            if threshold is not None or m.get("pass") is not None:
                raise ValueError(f"{name}: informational metrics must carry null threshold and pass")
            if not m.get("reason"):
                raise ValueError(f"{name}: informational metrics must record a reason")
            if not isinstance(m.get("value"), (int, float)):
                raise ValueError(f"{name}: informational metrics must carry a numeric value")
            continue
        if threshold != GATE_THRESHOLDS[name]:
            raise ValueError(f"{name}: threshold {threshold!r} != expected {GATE_THRESHOLDS[name]!r}")
        if state == "not_applicable":
            if m.get("value") is not None or m.get("pass") is not None:
                raise ValueError(f"{name}: not_applicable metrics must carry null value and pass")
            if not m.get("reason"):
                raise ValueError(f"{name}: not_applicable metrics must record a reason")
        elif state == "measured":
            if not isinstance(m.get("value"), (int, float)):
                raise ValueError(f"{name}: measured metrics must carry a numeric value")
            if not isinstance(m.get("pass"), bool):
                raise ValueError(f"{name}: measured metrics must carry a bool pass")
        else:
            raise ValueError(f"{name}: unknown state {state!r}")
    gate = manifest.get("gate", {})
    applicable_failures = [
        m["name"]
        for m in metrics
        if m["name"] in GATE_THRESHOLDS and m["state"] == "measured" and m["pass"] is False
    ]
    if gate.get("failures") != applicable_failures:
        raise ValueError("gate.failures does not match measured metric pass flags")
    expected_pass = not applicable_failures
    if gate.get("pass") != expected_pass:
        raise ValueError(f"gate.pass {gate.get('pass')!r} inconsistent with failures")
    deferred = gate.get("deferred")
    expected_deferred = sorted(m["name"] for m in metrics if m["state"] == "not_applicable")
    if sorted(deferred or []) != expected_deferred:
        raise ValueError("gate.deferred does not match not_applicable metrics")
    print(f"valid {GATE_SCHEMA_VERSION} manifest: {path}")
    return manifest


def gate_failure_reason(manifest: dict[str, Any]) -> str | None:
    """Return why the gate failed, or None when it passed.

    ``run_gate`` records the verdict inside the manifest, but CI reads the exit
    code, not the artifact: a command that stays green while ``gate.pass`` is
    false cannot fail for the thing it measures. Every thresholded metric here
    is a deterministic function of the synthetic corpus (recall, parse loss,
    discovery coverage, resume/handoff success), so a false verdict is a real
    regression rather than runner noise. Latency is measured without a
    threshold and never reaches this verdict.
    """
    gate = manifest.get("gate", {})
    if gate.get("pass") is True:
        return None
    failures = gate.get("failures") or []
    if failures:
        return "gate metrics below threshold: " + ", ".join(failures)
    return f"gate.pass is {gate.get('pass')!r}, not true"


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[2]
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="sync the labeled corpus, measure recall/latency, emit the gate manifest")
    run.add_argument("--profile", default="gate", help="profile name used in the manifest filename")
    run.add_argument("--workspace", default=str(root))
    run.add_argument("--output-dir", default=str(root / "scripts" / "evidence" / "out"))
    run.add_argument("--binary", help="explicit prebuilt release CLI; otherwise cargo build --release is run")
    run.add_argument("--cargo", default="cargo")
    run.add_argument("--sync-reps", type=int, default=1, help="sync repetitions for parse-loss aggregation")
    run.add_argument("--latency-reps", type=int, default=10, help="show/get latency repetitions")
    validate = sub.add_parser("validate-report", help="validate a gate manifest against the schema and thresholds")
    validate.add_argument("report")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "run":
            manifest_path = run_gate(args)
            reason = gate_failure_reason(
                json.loads(manifest_path.read_text(encoding="utf-8"))
            )
            if reason is not None:
                raise RuntimeError(reason)
        else:
            validate_manifest(Path(args.report).expanduser().resolve())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
