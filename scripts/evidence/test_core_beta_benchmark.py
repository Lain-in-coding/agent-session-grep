import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

MODULE_PATH = Path(__file__).with_name("core_beta_benchmark.py")
SPEC = importlib.util.spec_from_file_location("core_beta_benchmark", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)
ROOT = MODULE_PATH.resolve().parents[2]
HISTORICAL_REPORT = ROOT / "docs/evidence/core-beta/88d86f4/core-beta-benchmark-full.json"
STAMP = "2026-01-01T00:00:00Z"


def robot_frame(command: str, data: dict) -> dict:
    return {
        "ok": True, "outcome": "success", "command": command,
        "warnings": [], "page": {"has_more": False, "next_cursor": None},
        "data": data, "meta": {"duration_ms": 1},
    }


def process_result(stdout: bytes = b"agent-session-grep 0.0.0\n", **changes) -> dict:
    result = {
        "duration_ms": 3.0, "process_wall_ms": 2.0,
        "peak_rss_mb": None, "memory_observations": 0,
        "started_at_utc": STAMP, "completed_at_utc": STAMP,
        "returncode": 0, "timed_out": False,
        "stdout_bytes": stdout, "stderr_bytes": b"",
    }
    result.update(changes)
    return result


def oracle_fixture(root: Path, files: int = 2, per_file: int = 20, retained: int | None = None):
    """Small synthetic tables, assembled from source records rather than CLI output."""
    paths, _ = BENCHMARK.write_dataset(root, files, per_file)
    retained = per_file if retained is None else retained
    if retained != per_file:
        if retained != per_file // 2:
            raise ValueError("test fixture only supports intact or half retained")
        BENCHMARK.shrink_dataset(paths)
    tables = {
        "catalog": {}, "placements": [], "edges": [], "claims": [],
        "members": [], "scans": [], "relations": [], "fts_ids": set(),
        "generation": 1 if retained == per_file else 2, "retained": retained,
    }
    for file_index, path in enumerate(paths):
        source = str(path.resolve())
        document = f"doc_v1_fixture{file_index:04d}"
        session = f"ses_v1_fixture{file_index:04d}"
        contents = path.read_bytes()
        fingerprint = "sha256:" + hashlib.sha256(contents).hexdigest()
        wires = []
        offset = 0
        for local, line in enumerate(contents.splitlines()):
            record = json.loads(line)
            wire = "msg_v1_" + record["uuid"]
            parent = "msg_v1_" + record["parentUuid"] if record["parentUuid"] else None
            placement = f"plc_fixture{file_index:04d}_{local:04d}"
            tables["catalog"][wire] = {
                "role": record["type"], "text": record["message"]["content"],
                "timestamp": record["timestamp"], "session": session,
                "sessions": [session], "parent": parent,
                "is_sidechain": record["isSidechain"],
            }
            tables["placements"].append((placement, session, document, wire, local,
                                         int(record["isSidechain"]), offset, offset + len(line)))
            if parent is not None:
                tables["edges"].append((placement, parent, "subagent" if record["isSidechain"] else "reply"))
            tables["claims"].append((source, placement))
            tables["members"].append((source, wire, document))
            tables["fts_ids"].add(wire)
            wires.append(wire)
            offset += len(line) + 1
        tables["catalog"][document] = {"len": len(contents), "fingerprint": fingerprint}
        tables["catalog"][session] = {"messages": wires, "documents": [document]}
        tables["members"].extend((source, wire, document) for wire in (document, session))
        tables["scans"].append((source, len(contents), fingerprint))
        tables["relations"].append((source,))
    oracle = BENCHMARK.SyntheticOracle(paths, per_file)
    return oracle, tables


def context_frame(oracle, tables: dict, order: list[int]) -> dict:
    messages, evidence = [], []
    for index in order:
        binding = oracle.bindings[index]
        messages.append({
            "id": binding["message_id"], "message_id": binding["message_id"],
            "placement_id": binding["placement_id"],
            "payload": copy.deepcopy(tables["catalog"][binding["message_id"]]),
        })
        evidence.append({
            "occurrence_id": binding["placement_id"], "message_id": binding["message_id"],
            "source_document_id": binding["source_document_id"],
            "source_fingerprint": binding["source_fingerprint"],
            "byte_start": binding["byte_start"], "byte_end": binding["byte_end"],
            "record_ordinal": binding["source_ordinal"], "generation": oracle.generation,
            "precision": "byte", "line_start": None, "line_end": None,
            "snippet_char_start": None, "snippet_char_end": None,
        })
    leaf = oracle.bindings[order[-1]]
    return robot_frame("context", {
        "session_id": oracle.bindings[0]["session_id"], "generation": oracle.generation,
        "requested_level": "raw", "effective_level": "raw", "messages": messages,
        "evidence": evidence, "branch_leaf": leaf["message_id"],
        "branch_leaf_placement_id": leaf["placement_id"],
        "session": {"messages": [oracle.bindings[index]["message_id"] for index in range(oracle.retained)],
                    "documents": [oracle.bindings[0]["source_document_id"]]},
        "tool_activities": [], "truncation": {"truncated": False, "reason": None},
    })


def fixture_hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def source_receipt() -> dict:
    return {
        "commit": "1" * 40, "harness_commit": "1" * 40, "checker_commit": "1" * 40,
        "harness_path": "scripts/evidence/core_beta_benchmark.py",
        "harness_sha256": fixture_hash("harness"), "checker_sha256": fixture_hash("harness"),
        "cargo_lock_sha256": fixture_hash("lock"), "cargo_manifest_sha256": fixture_hash("manifest"),
        "repository": "Lain-in-coding/agent-session-grep",
        "cleanliness": {"tracked": "clean", "index": "clean", "untracked": "clean"},
    }


def build_receipt(source: dict | None = None, binary: bytes = b"synthetic binary") -> dict:
    return {
        "schema_version": "agent-session-grep.baseline-build/v1", "origin_run": 1,
        "source": source or source_receipt(),
        "configuration": {
            "target": "x86_64-pc-windows-msvc",
            "rustc": "rustc 1.97.1\nhost: x86_64-pc-windows-msvc",
            "cargo_tool_sha256": fixture_hash("cargo"), "rustc_tool_sha256": fixture_hash("rustc"),
            "environment": {"CARGO_BUILD_TARGET": None, "CARGO_BUILD_JOBS": None,
                            "CARGO_TARGET_DIR": "source-root/target"},
            "cargo_configuration": "none", "compiler_link_overrides": "none",
        },
        "cargo_version": "cargo 1.97.1",
        "command": ["cargo", "build", "--locked", "--release", "-p",
                    "agent-session-grep-cli", "--message-format=json"],
        "features": [], "release_profile": {"opt_level": "3", "debuginfo": 0,
                                            "debug_assertions": False, "overflow_checks": False,
                                            "test": False},
        "artifact_was_cached": False, "artifact_relative_to_target": "release/agent-session-grep.exe",
        "binary_sha256": hashlib.sha256(binary).hexdigest(), "binary_size_bytes": len(binary),
        "sqlite": {
            "package": "libsqlite3-sys", "package_version": "0.38.2", "sqlite_version": "3.53.2",
            "archive_sha256": fixture_hash("archive"), "header_sha256": fixture_hash("header"),
            "source_sha256": fixture_hash("source"), "build_script_sha256": fixture_hash("build script"),
            "method": "locked-bundled-source-and-build-linkage", "runtime_query": False,
            "features": ["bundled", "bundled_bindings"], "linked_libraries": ["static=sqlite3"],
            "native_library_sha256": fixture_hash("native library"), "native_library_size_bytes": 128,
        },
        "linkage": "harness-build-receipt-not-independent-attestation",
    }


def build_receipt_from_artifacts(root: Path, target: str, libraries: dict[str, bytes],
                                linked_libraries: list[str] | None = None) -> dict:
    """Exercise the real receipt producer with local files and Cargo JSON only."""
    template = build_receipt()
    source, config = template["source"], template["configuration"]
    config.update(target=target, rustc=f"rustc 1.97.1\nhost: {target}")
    target_dir, suite = root / "target", root / "suite"
    output = target_dir / "release/build/sqlite/out"
    output.mkdir(parents=True)
    suite.mkdir()
    for name, content in libraries.items():
        (output / name).write_bytes(content)
    binary = target_dir / "release" / ("agent-session-grep.exe" if "windows" in target else "agent-session-grep")
    binary.write_bytes(b"synthetic binary")
    metadata = {"packages": [{"name": "libsqlite3-sys", "id": "sqlite-package"},
                             {"name": "agent-session-grep-cli", "id": "cli-package"}],
                "target_directory": str(target_dir)}
    events = [
        {"reason": "compiler-artifact", "package_id": "cli-package",
         "target": {"name": "agent-session-grep"}, "executable": str(binary),
         "profile": template["release_profile"], "features": [], "fresh": False},
        {"reason": "compiler-artifact", "package_id": "sqlite-package",
         "target": {"kind": ["lib"]}, "features": ["bundled", "bundled_bindings"]},
        {"reason": "build-script-executed", "package_id": "sqlite-package",
         "out_dir": str(output), "linked_paths": ["native=" + str(output)],
         "linked_libs": ["static=sqlite3"] if linked_libraries is None else linked_libraries},
        {"reason": "build-finished", "success": True},
    ]
    replies = {"metadata": json.dumps(metadata),
               "build": "\n".join(json.dumps(event) for event in events),
               "--version": "cargo 1.97.1"}
    args = argparse.Namespace(cargo="cargo", expected_commit=source["commit"])
    with patch.object(BENCHMARK, "checked_command", side_effect=lambda command, *args, **kwargs: replies[command[1]]), \
         patch.object(BENCHMARK, "locked_sqlite", return_value={}), \
         patch.object(BENCHMARK, "sqlite_source_proof", return_value=copy.deepcopy(template["sqlite"])), \
         patch.object(BENCHMARK, "source_identity", return_value=source):
        _, receipt = BENCHMARK.build_receipt(root, suite, args, source, config, root)
    BENCHMARK.validate_build_receipt(receipt, source)
    return receipt


def mock_corpus_identity(files: int, per_file: int, retained: int) -> dict:
    """Metadata-only matrix fixture; no 2k/10k/50k corpus is generated by tests."""
    return {
        "file_count": files, "messages_per_file": per_file, "retained_per_file": retained,
        "source_occurrences": files * retained, "source_bytes": files * retained * 128,
        "hash_algorithm": "sha256", "tree_hash": fixture_hash(f"corpus:{files}:{per_file}:{retained}"),
    }


def matrix_context_anchor(size: int) -> dict:
    lines = BENCHMARK.fixture_lines(0, size, size)
    fingerprint = fixture_hash(f"fingerprint:{size}")
    anchor = {
        "generator_file": 0, "session_id": "ses_v1_" + "2" * 32,
        "source_document_id": "doc_v1_" + "3" * 32,
        "source_fingerprint": fingerprint,
        "source_sha256": hashlib.sha256(b"\n".join(lines) + b"\n").hexdigest(),
        "members": [], "mainline_order": BENCHMARK.fixture_context_order(list(range(size)), size, "mainline"),
        "full_order": BENCHMARK.fixture_context_order(list(range(size)), size, "full"),
    }
    offset = 0
    for index, line in enumerate(lines):
        anchor["members"].append({
            "generator_index": index, "message_id": f"msg_v1_00000000-0000-4000-8000-{index:012d}",
            "placement_id": f"plc_v1_{index:032x}", "session_id": anchor["session_id"],
            "source_document_id": anchor["source_document_id"], "source_ordinal": index,
            "byte_start": offset, "byte_end": offset + len(line), "source_fingerprint": fingerprint,
        })
        offset += len(line) + 1
    return anchor


def matrix_section(name: str, files: int, per_file: int, run: int, next_ordinal: int):
    section = BENCHMARK.new_section(name, files, per_file)
    if name != "anchor":
        section["context_anchor"] = matrix_context_anchor(per_file)
    for trial in range(1, 2 if name == "preflight" else 4):
        for phase in ("initial", "noop", "shrink"):
            retained = per_file // 2 if phase == "shrink" else per_file
            corpus = mock_corpus_identity(files, per_file, retained)
            count = files * retained
            census = {
                "messages": count, "placements": count, "sessions": files, "documents": files,
                "sources": files, "edges": files * (retained - ((retained + 9) // 10)),
                "catalog_entities": count + 2 * files, "fts_messages": count,
                "source_placement_claims": count, "source_entity_claims": count + 2 * files,
                "generation": 2 if phase == "shrink" else 1,
                "retained_verified": count, "removed_verified": files * (per_file - retained),
                "bindings_sha256": fixture_hash(f"{name}:{trial}:{retained}"),
            }
            section["snapshots"].append({
                "phase": phase, "trial": trial, "corpus": corpus, "census": census,
                "store": {"files": [{"name": "catalog.db", "bytes": 4096},
                                    {"name": "catalog.db-wal", "bytes": 128}],
                          "total_bytes": 4224,
                          "coverage": "catalog.db-and-present-sidecars-after-exit-no-explicit-checkpoint"},
            })
    for planned in BENCHMARK.expected_observation_sequence(section):
        operation, phase = planned["operation"], planned["phase"]
        generation = 2 if phase in ("shrink", "post_shrink") else 1
        if operation.startswith("startup_"):
            correctness = {"version_sha256": fixture_hash("version")}
        elif operation == "sync":
            count = files * (per_file // 2 if phase == "shrink" else per_file)
            correctness = {"sources": files, "emitted": 0 if phase == "noop" else count,
                           "messages": 0 if phase == "noop" else count,
                           "committed": 0 if phase == "noop" else count,
                           "unchanged": count if phase == "noop" else 0,
                           "retained": 0, "deferred": 0, "skipped": 0, "diagnostics": 0,
                           "generation": generation}
        elif operation == "search":
            correctness = {"generation": generation, "hit_count": 20,
                           "result_ids_sha256": fixture_hash("results")}
        elif operation in ("show", "get"):
            index = planned["generator_index"]
            correctness = {"generator_index": index,
                           "message_id": f"msg_v1_00000000-0000-4000-8000-{index:012d}"}
        elif operation == "context":
            order = section["context_anchor"][planned["policy"] + "_order"]
            correctness = {"generation": generation, "message_count": len(order),
                           "order_sha256": BENCHMARK.json_hash(order), "evidence_count": len(order)}
        else:
            correctness = {"command_verified": "doctor"}
        started = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
            seconds=(run - 1) * 60, milliseconds=next_ordinal * 10)
        section["observations"].append({
            **planned, "ordinal": next_ordinal, "workload": name,
            "started_at_utc": started.isoformat().replace("+00:00", "Z"),
            "completed_at_utc": (started + timedelta(milliseconds=2)).isoformat().replace("+00:00", "Z"),
            "process_wall_ms": 2.0, "legacy_duration_ms": 3.0, "stdout_bytes": 128,
            "cli_reported_duration_ms": None if operation.startswith("startup_") else 1,
            "exit_code": 0, "outcome": "success",
            "memory": {"peak_rss_mib": 4.0 if next_ordinal % 2 else None,
                       "method": "windows_peak_working_set", "interval_ms": 100,
                       "observation_count": 1 if next_ordinal % 2 else 0,
                       "unavailable_reason": None if next_ordinal % 2 else "no_observations"},
            "correctness": correctness,
        })
        next_ordinal += 1
    section["summaries"] = BENCHMARK.section_summaries(section)
    section["derived"] = BENCHMARK.section_derived(section)
    return section, next_ordinal


def baseline_report(run: int = 1) -> dict:
    """Complete synthetic metadata, never performance evidence or a live run."""
    report = json.loads(HISTORICAL_REPORT.read_text(encoding="utf-8"))
    source, receipt = source_receipt(), build_receipt()
    next_ordinal = 1
    preflight, next_ordinal = matrix_section("preflight", 1, 20, run, next_ordinal)
    anchor, next_ordinal = matrix_section("anchor", 20, 200, run, next_ordinal)
    workloads = []
    for name in BENCHMARK.scale_order(run):
        section, next_ordinal = matrix_section(name, dict(BENCHMARK.SCALES)[name], 200, run, next_ordinal)
        workloads.append(section)
    plan = BENCHMARK.baseline_plan(run)
    plan["memory_method"] = "windows_peak_working_set"
    report.update(commit=source["commit"], generated_at_utc=STAMP)
    report["binary"].update(binary_hash=receipt["binary_sha256"], artifact_size_bytes=receipt["binary_size_bytes"],
                            provenance="built_by_harness_from_workspace" if run == 1 else "caller_supplied_prebuilt")
    report["environment"] = {
        "os": "windows", "target_triple": receipt["configuration"]["target"],
        "cpu": "synthetic CPU", "logical_cpu_count": 8, "ram_gb": 32.0,
        "disk": "synthetic NVMe", "filesystem": "NTFS", "antivirus_state": "enabled",
        "architecture": "AMD64", "os_release": "synthetic", "os_version": "synthetic",
        "python_version": "3.10.11", "rustc": receipt["configuration"]["rustc"],
        "python_sqlite_version_not_store_version": "3.0.0",
        "sqlite_version": receipt["sqlite"]["sqlite_version"],
        "sqlite_version_source": "locked bundled source + this build linkage; no direct CLI runtime query",
        "captured_at_utc": STAMP,
    }
    corpus = mock_corpus_identity(20, 200, 200)
    report["dataset"].update(dataset_hash=corpus["tree_hash"], source_bytes=corpus["source_bytes"])
    for name, metric in report["metrics"].items():
        records = [record for record in anchor["observations"] if record["legacy_metric"] == name]
        values = ([record["legacy_duration_ms"] for record in records] if records else
                  [round(corpus["source_bytes"] / 1024**2 / 0.003, 6)] * 3)
        peaks = [record["memory"]["peak_rss_mib"] for record in records
                 if record["memory"]["peak_rss_mib"] is not None]
        metric.update(raw_samples=values, summary=BENCHMARK.rounded_summary(values),
                      peak_rss_mb_raw_samples=peaks,
                      peak_rss_mb_summary=BENCHMARK.rounded_summary(peaks) if peaks else None)
    peaks = [value for metric in report["metrics"].values() for value in metric["peak_rss_mb_raw_samples"]]
    report["aggregate_peak_rss_mb"] = {"raw_samples": peaks, "summary": BENCHMARK.rounded_summary(peaks)}
    report["sizes"].update(artifact_size_bytes=receipt["binary_size_bytes"], dataset_source_bytes=corpus["source_bytes"],
                           initial_store_bytes_including_sidecars=4224, post_shrink_store_bytes_including_sidecars=4224,
                           index_size_ratio=round(4224 / corpus["source_bytes"], 6),
                           initial_store_bytes_raw_samples=[4224] * 3,
                           initial_store_files=["catalog.db", "catalog.db-wal"],
                           post_shrink_store_files=["catalog.db", "catalog.db-wal"])
    report["recovery"]["observation"].update(doctor_open_duration_ms=3.0, active_generation=2)
    report["limitations"] = ["Synthetic test metadata; not measured performance."]
    if run != 1:
        report["limitations"].append("Prebuilt binary source-to-binary linkage is not independently attested.")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=(run - 1) * 60)
    report["baseline"] = {
        "schema_version": "agent-session-grep.current-source-baseline/v1", "suite_id": "synthetic-suite",
        "run_ordinal": run, "started_at_utc": start.isoformat().replace("+00:00", "Z"),
        "completed_at_utc": (start + timedelta(seconds=40)).isoformat().replace("+00:00", "Z"),
        "suite_started_at_utc": STAMP, "suite_started_monotonic_ns": 1_000_000_000,
        "started_elapsed_ms": (run - 1) * 60000.0, "completed_elapsed_ms": (run - 1) * 60000.0 + 40000.0,
        "source_before": source, "source_after": copy.deepcopy(source),
        "build_receipt": receipt, "build_receipt_sha256": BENCHMARK.json_hash(receipt),
        "binary_use": "built_in_run_1" if run == 1 else "reused_run_1_receipt",
        "child_policy": dict(BENCHMARK.CHILD_POLICY), "plan": plan,
        "preflight": preflight, "anchor": anchor, "workloads": workloads,
        "coverage": {"complete": True, "independent_catalog_oracle": True, "failed_observations": 0,
                     "trace": "separate-local-trial-after-primary-run-3",
                     "limitations": ["Synthetic metadata fixture; no actual scale measurement."]},
    }
    return report


class BenchmarkStatisticsTests(unittest.TestCase):
    def test_nearest_rank_percentiles(self) -> None:
        samples = [float(value) for value in range(1, 101)]
        summary = BENCHMARK.rounded_summary(samples)
        self.assertEqual(summary["p50"], 50.0)
        self.assertEqual(summary["p95"], 95.0)
        self.assertEqual(summary["p99"], 99.0)
        self.assertEqual(summary["count"], 100)

    def test_single_sample_stddev_is_zero(self) -> None:
        self.assertEqual(BENCHMARK.rounded_summary([12.5])["sample_stddev"], 0.0)

    def test_summary_validation_rejects_tampering(self) -> None:
        samples = [1.0, 2.0, 3.0]
        summary = BENCHMARK.rounded_summary(samples)
        summary["p95"] = 999.0
        with self.assertRaises(ValueError):
            BENCHMARK.assert_summary(samples, summary, "peak_rss_mb")

    def test_synthetic_dataset_is_byte_deterministic(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first = Path(first_name)
            second = Path(second_name)
            first_files, first_ids = BENCHMARK.write_dataset(first, 2, 6)
            second_files, second_ids = BENCHMARK.write_dataset(second, 2, 6)
            self.assertEqual(first_ids, second_ids)
            self.assertEqual(
                BENCHMARK.tree_hash(first_files, first),
                BENCHMARK.tree_hash(second_files, second),
            )
            self.assertNotIn(str(Path.home()), first_files[0].read_text(encoding="utf-8"))


class BaselineStatisticsTests(unittest.TestCase):
    def test_mad_uses_nearest_rank_raw_precision_without_trimming(self) -> None:
        result = BENCHMARK.baseline_summary([1.000001, 1.000003, 4.000003, 100.0])
        self.assertEqual(result["p50"], 1.000003)
        self.assertEqual(result["mad"], 0.000002)
        self.assertEqual(result["count"], 4)
        self.assertEqual(result["p95"], 100.0)
        self.assertEqual(result["max"], 100.0)
        self.assertEqual(BENCHMARK.baseline_summary([3.5])["mad"], 0.0)

    def test_spread_exact_boundary_and_zero_denominators(self) -> None:
        for values, spread, warning, reason in (
            ([85.0, 100.0, 100.0], 15.0, False, None),
            ([84.999999, 100.0, 100.0], 15.000001, True, None),
            ([0.0, 0.0, 0.0], 0.0, False, None),
            ([0.0, 0.0, 1.0], None, True, "zero_median_with_positive_range"),
        ):
            with self.subTest(values=values):
                result = BENCHMARK.median_spread(values)
                self.assertEqual(result["run_p50_ms"], values)
                self.assertEqual(result["spread_percent"], spread)
                self.assertIs(result["noise_warning"], warning)
                self.assertEqual(result["reason"], reason)

    def test_spread_rejects_bad_count_and_nonfinite_or_boolean_values(self) -> None:
        for values in ([], [1.0], [1.0] * 4, [1.0, True, 2.0],
                       [-1.0, 0.0, 1.0], [1.0, float("nan"), 2.0],
                       [1.0, float("inf"), 2.0]):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "run medians"):
                BENCHMARK.median_spread(values)

    def test_failed_measured_observation_cannot_enter_summary(self) -> None:
        for outcome, code in (("timeout", -9), ("oracle_mismatch", 0), ("nonzero_exit", 10)):
            section = {"observations": [{"role": "measured", "outcome": outcome, "exit_code": code}]}
            with self.subTest(outcome=outcome), self.assertRaisesRegex(ValueError, "failed observation"):
                BENCHMARK.section_summaries(section)


class ProcessObservationTests(unittest.TestCase):
    def test_single_lifecycle_captures_both_clock_endpoints(self) -> None:
        events = []
        clock_values = iter((1_000_000_000, 1_012_000_000, 1_037_000_000))

        def clock():
            events.append("clock")
            return next(clock_values)

        def communicate():
            events.append("communicate")
            return "配置\n".encode(), b""

        process = Mock(returncode=0)
        process.poll.return_value = 0
        process.communicate.side_effect = communicate

        def thread(target, daemon):
            self.assertTrue(daemon)
            return SimpleNamespace(start=target, join=lambda timeout: events.append("join"))

        with patch.object(BENCHMARK.subprocess, "Popen", return_value=process) as launch, \
             patch.object(BENCHMARK.threading, "Thread", side_effect=thread), \
             patch.object(BENCHMARK, "peak_working_set_bytes", return_value=2 * 1024**2), \
             patch.object(BENCHMARK.time, "perf_counter_ns", side_effect=clock), \
             patch.object(BENCHMARK, "utc_now", side_effect=[STAMP, STAMP]):
            result = BENCHMARK.process_lifecycle(["synthetic-cli"], ROOT, detailed=True)
        self.assertEqual(events, ["clock", "communicate", "clock", "join", "clock"])
        launch.assert_called_once()
        self.assertEqual(result["process_wall_ms"], 12.0)
        self.assertEqual(result["duration_ms"], 37.0)
        self.assertEqual(result["stdout_bytes"], "配置\n".encode())
        self.assertEqual(result["peak_rss_mb"], 2.0)
        self.assertEqual(result["memory_observations"], 1)

    def test_imported_process_adapter_preserves_dict_environment_and_failures(self) -> None:
        command, environment = ["synthetic-cli"], {"ASG_CLOCK_MS": "17"}
        with patch.object(BENCHMARK, "process_lifecycle", return_value=process_result()) as lifecycle:
            actual = BENCHMARK.run_process(command, ROOT)
            lifecycle.assert_called_once_with(command, ROOT, None)
            self.assertEqual(actual, {"duration_ms": 3.0, "peak_rss_mb": None,
                                      "stdout": "agent-session-grep 0.0.0\n"})
            lifecycle.reset_mock()
            BENCHMARK.run_process(command, ROOT, environment)
            lifecycle.assert_called_once_with(command, ROOT, environment)
            lifecycle.return_value = process_result(returncode=10)
            with self.assertRaisesRegex(RuntimeError, "command failed \\(10\\)"):
                BENCHMARK.run_process(command, ROOT)
            lifecycle.return_value = process_result(stdout=b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                BENCHMARK.run_process(command, ROOT)

    def test_timeout_kills_and_drains_child_and_keeps_partial_output(self) -> None:
        process = Mock(returncode=-9)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("synthetic-cli", 0.49, output=b"part"),
            (b"partial output\n", b"stopped"),
        ]
        with patch.object(BENCHMARK.subprocess, "Popen", return_value=process), \
             patch.object(BENCHMARK.threading, "Thread"), \
             patch.object(BENCHMARK.time, "perf_counter_ns", side_effect=[
                 1_000_000_000, 1_010_000_000, 1_015_000_000, 1_020_000_000]):
            result = BENCHMARK.process_lifecycle(["synthetic-cli"], ROOT, timeout=0.5)
        process.kill.assert_called_once_with()
        self.assertAlmostEqual(process.communicate.call_args_list[0].kwargs["timeout"], 0.49)
        self.assertEqual(process.communicate.call_args_list[1].kwargs, {"timeout": 5.0})
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["returncode"], -9)
        self.assertEqual(result["stdout_bytes"], b"partial output\n")
        self.assertIsNone(result["peak_rss_mb"])
        self.assertEqual(result["memory_observations"], 0)

    def test_child_environment_removes_only_owned_overrides(self) -> None:
        parent = {"PATH": "bootstrap", "SystemRoot": "system", "UNRELATED": "keep",
                  "ASG_INDEX_TRACE": "inherited", "asg_current_repo": "inherited",
                  "Asg_Clock_Ms": "123"}
        before = parent.copy()
        child = BENCHMARK.baseline_environment(parent)
        self.assertEqual(parent, before)
        self.assertEqual(child, {"PATH": "bootstrap", "SystemRoot": "system", "UNRELATED": "keep"})
        self.assertIsNot(child, parent)
        trace = Path("synthetic-trace.jsonl")
        traced = BENCHMARK.baseline_environment(parent, trace=trace)
        self.assertEqual(traced, {**child, "ASG_INDEX_TRACE": str(trace)})
        with patch.dict(os.environ, parent, clear=True):
            original = dict(os.environ)
            BENCHMARK.baseline_environment()
            self.assertEqual(dict(os.environ), original)

    def test_observation_counts_utf8_lf_bytes_and_keeps_null_memory_alignment(self) -> None:
        frame = robot_frame("show", {"entity": {"text": "配置"}})
        raw = (json.dumps(frame, ensure_ascii=False) + "\n").encode()
        budget = Mock()
        budget.remaining.return_value = 300.0
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            context = BENCHMARK.BaselineRun(ROOT, root / "cli", root, budget, 1)
            section = BENCHMARK.new_section("preflight", 1, 20)
            with patch.object(BENCHMARK, "process_lifecycle", return_value=process_result(raw)) as lifecycle:
                context.invoke(section, [str(context.binary)], "show", "intact", 1,
                               "verification", 1, check=lambda value: {"verified": True})
        record = section["observations"][0]
        self.assertEqual(record["stdout_bytes"], len(raw))
        self.assertGreater(len(raw), len(raw.decode()))
        self.assertEqual(record["memory"]["observation_count"], 0)
        self.assertIsNone(record["memory"]["peak_rss_mib"])
        self.assertEqual(record["memory"]["unavailable_reason"], "no_observations")
        self.assertEqual(record["cli_reported_duration_ms"], 1)
        self.assertEqual(record["argv"], ["binary"])
        self.assertNotIn("stdout", record)
        self.assertEqual(lifecycle.call_args.kwargs, {"timeout": 300, "detailed": True})

    def test_failed_invocations_remain_in_attempt_and_cannot_be_summarized(self) -> None:
        cases = [
            (process_result(timed_out=True, returncode=-9), "timeout"),
            (process_result(returncode=10), "nonzero_exit"),
            (process_result(b"invalid output"), "invalid_output"),
        ]
        for result, outcome in cases:
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                budget = Mock()
                budget.remaining.return_value = 300.0
                context = BENCHMARK.BaselineRun(ROOT, root / "cli", root, budget, 1)
                section = context.anchor
                with patch.object(BENCHMARK, "process_lifecycle", return_value=result) as launch, \
                     self.assertRaises(ValueError):
                    context.invoke(section, [str(context.binary), "--version"],
                                   "startup_warm", "warm", 0, "measured", 1)
                launch.assert_called_once()
                self.assertEqual(len(section["observations"]), 1)
                self.assertEqual(section["observations"][0]["outcome"], outcome)
                with self.assertRaises(ValueError):
                    BENCHMARK.section_summaries(section)


class SyntheticCorrectnessTests(unittest.TestCase):
    def test_mainline_keeps_sidechain_ancestor_and_full_uses_timestamp_order(self) -> None:
        self.assertEqual(BENCHMARK.fixture_context_order(list(range(20)), 20, "mainline"),
                         list(range(10, 20)))
        self.assertIn(17, BENCHMARK.fixture_context_order(list(range(20)), 20, "mainline"))
        self.assertEqual(BENCHMARK.fixture_context_order(list(range(30)), 30, "full"),
                         [0, 28, 1, 29, *range(2, 28)])
        self.assertEqual(BENCHMARK.fixture_context_order([0], 20, "mainline"), [0])

    def test_initial_noop_shrink_counts_and_generations(self) -> None:
        for phase, count, generation in (("initial", 40, 1), ("noop", 40, 1), ("shrink", 20, 2)):
            with self.subTest(phase=phase):
                data = {"sources": 2, "emitted": 0 if phase == "noop" else count,
                        "messages": 0 if phase == "noop" else count,
                        "committed": 0 if phase == "noop" else count,
                        "unchanged": count if phase == "noop" else 0,
                        "retained": 0, "deferred": 0, "skipped": 0, "diagnostics": 0,
                        "generation": generation}
                self.assertEqual(BENCHMARK.sync_check(robot_frame("sync", data), 2, count, phase), data)
                for key, value in (("generation", generation + 1), ("skipped", 1),
                                   ("committed", True), ("retained", 1)):
                    with self.subTest(field=key), self.assertRaises(ValueError):
                        BENCHMARK.sync_check(robot_frame("sync", {**data, key: value}), 2, count, phase)

    def test_census_verifies_retained_and_removed_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for retained, count, edges, generation in ((20, 40, 36, 1), (10, 20, 18, 2)):
                with self.subTest(retained=retained):
                    oracle, tables = oracle_fixture(root / str(retained), retained=retained)
                    census = oracle.check_tables(**tables)
                    self.assertEqual(census["messages"], count)
                    self.assertEqual(census["placements"], count)
                    self.assertEqual(census["sessions"], 2)
                    self.assertEqual(census["edges"], edges)
                    self.assertEqual(census["catalog_entities"], count + 4)
                    self.assertEqual(census["retained_verified"], count)
                    self.assertEqual(census["removed_verified"], 40 - count)
                    self.assertEqual(census["generation"], generation)

    def test_census_rejects_missing_claims_edges_fts_and_wrong_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oracle, original = oracle_fixture(Path(directory))
            mutations = {
                "fts": lambda tables: tables["fts_ids"].pop(),
                "edge": lambda tables: tables["edges"].pop(),
                "claim": lambda tables: tables["claims"].pop(),
                "member": lambda tables: tables["members"].pop(),
                "relation": lambda tables: tables["relations"].pop(),
                "placement": lambda tables: tables["placements"].pop(),
                "generation": lambda tables: tables.update(generation=2),
                "extra_removed_message": lambda tables: tables["catalog"].update(msg_v1_removed={}),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    tables = copy.deepcopy(original)
                    mutate(tables)
                    with self.assertRaises(ValueError):
                        oracle.check_tables(**tables)

    def test_read_only_scan_preserves_catalog_and_pre_census_wal_footprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            oracle, tables = oracle_fixture(root / "d")
            absent = root / "missing.db"
            with self.assertRaisesRegex(ValueError, "catalog missing"):
                oracle.scan(absent, 20)
            self.assertFalse(absent.exists())
            db = root / "catalog.db"
            definitions = (
                ("catalog", "id, payload", [(key, json.dumps(value)) for key, value in tables["catalog"].items()]),
                ("message_placements", "placement_id, session_id, document_id, message_id, source_ordinal, is_sidechain, byte_start, byte_end", tables["placements"]),
                ("message_edges", "child_placement_id, parent_message_id, relation", tables["edges"]),
                ("source_placement_membership", "source_path, placement_id", tables["claims"]),
                ("source_membership", "source_path, message_id, document_id", tables["members"]),
                ("source_scans", "source_path, len_bytes, fingerprint", tables["scans"]),
                ("source_relation_scans", "source_path", tables["relations"]),
                ("fts", "text", [("synthetic",) for _ in tables["fts_ids"]]),
                ("fts_ids", "wire_id, fts_rowid", [(wire, index) for index, wire in enumerate(sorted(tables["fts_ids"]), 1)]),
                ("store_metadata", "singleton, active_generation", [(1, 1)]),
            )
            with closing(sqlite3.connect(db)) as connection, connection:
                connection.execute("PRAGMA journal_mode=WAL")
                for name, columns, rows in definitions:
                    connection.execute(f"CREATE TABLE {name} ({columns})")
                    placeholders = ",".join("?" for _ in columns.split(","))
                    connection.executemany(f"INSERT INTO {name} VALUES ({placeholders})", rows)
            before = db.read_bytes()
            before_files = [{"name": path.name, "bytes": path.stat().st_size}
                            for path in sorted(root.glob("catalog.db*")) if path.is_file()]
            connect, opened = sqlite3.connect, []

            def track_connection(*args, **kwargs):
                self.assertTrue(kwargs["uri"])
                self.assertTrue(args[0].endswith("?mode=ro"))
                connection = connect(*args, **kwargs)
                opened.append(connection)
                return connection

            context = BENCHMARK.BaselineRun(ROOT, root / "cli", root, Mock(), 1)
            section = BENCHMARK.new_section("preflight", 2, 20)
            with patch.object(BENCHMARK.sqlite3, "connect", side_effect=track_connection):
                context.snapshot(section, db, oracle, "initial", 1)
            snapshot = section["snapshots"][0]
            self.assertEqual(snapshot["census"]["messages"], 40)
            # mode=ro still permits WAL/SHM creation in a writable directory.
            # The measured store must exclude this observer's side effects.
            self.assertEqual(snapshot["store"]["files"], before_files)
            self.assertEqual(snapshot["store"]["total_bytes"], sum(item["bytes"] for item in before_files))
            self.assertEqual(len(opened), 1)
            with self.assertRaises(sqlite3.ProgrammingError):
                opened[0].execute("SELECT 1")
            self.assertEqual(db.read_bytes(), before)
            with closing(sqlite3.connect(db)) as connection, connection:
                connection.execute("INSERT INTO fts VALUES ('orphan synthetic row')")
            with patch.object(BENCHMARK.sqlite3, "connect", side_effect=track_connection), \
                 self.assertRaisesRegex(ValueError, "orphan or duplicate FTS"):
                oracle.scan(db, 20)
            with self.assertRaises(sqlite3.ProgrammingError):
                opened[-1].execute("SELECT 1")

    def test_show_get_reject_another_entity_and_payload_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oracle, tables = oracle_fixture(Path(directory))
            oracle.check_tables(**tables)
            entity = tables["catalog"][oracle.bindings[1]["message_id"]]
            other = tables["catalog"][oracle.bindings[2]["message_id"]]
            for operation in ("show", "get"):
                def frame(value):
                    return robot_frame(operation, {"entity": value} if operation == "show"
                                       else {"payload": json.dumps(value)})
                self.assertEqual(oracle.check_read(frame(entity), operation, 1)["generator_index"], 1)
                for value in (other, {**entity, "session": "ses_v1_wrong"},
                              {**entity, "text": "incorrect"}, {**entity, "role": "system"}):
                    with self.subTest(operation=operation, value=value), self.assertRaises(ValueError):
                        oracle.check_read(frame(value), operation, 1)

    def test_search_checks_all_classes_identity_relevance_and_first_page(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oracle, tables = oracle_fixture(Path(directory))
            oracle.check_tables(**tables)
            for query_class, query in zip(BENCHMARK.QUERY_CLASSES, BENCHMARK.QUERIES):
                token = query.strip('"')
                all_hits = [{"id": wire, "text": tables["catalog"][wire]["text"],
                             "session_id": tables["catalog"][wire]["session"]}
                            for wire in sorted(oracle.by_wire)
                            if token in tables["catalog"][wire]["text"]]
                frame = robot_frame("search", {"retrieval_mode": "lexical", "generation": 1,
                                                "hits": all_hits[:20]})
                frame["page"] = {"has_more": len(all_hits) > 20,
                                 "next_cursor": "synthetic-cursor" if len(all_hits) > 20 else None}
                self.assertEqual(oracle.check_search(frame, query_class)["hit_count"], min(20, len(all_hits)))
                for key, value in (("generation", 2), ("retrieval_mode", "hybrid"), ("hits", [])):
                    bad = copy.deepcopy(frame)
                    bad["data"][key] = value
                    with self.subTest(query_class=query_class, field=key), self.assertRaises(ValueError):
                        oracle.check_search(bad, query_class)
                bad = copy.deepcopy(frame)
                bad["data"]["hits"][0]["text"] = "irrelevant"
                with self.assertRaises(ValueError):
                    oracle.check_search(bad, query_class)
                bad = copy.deepcopy(frame)
                bad["data"]["hits"][1] = bad["data"]["hits"][0]
                with self.assertRaises(ValueError):
                    oracle.check_search(bad, query_class)

    def test_context_membership_order_leaf_evidence_and_partial_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oracle, tables = oracle_fixture(Path(directory))
            oracle.check_tables(**tables)
            for policy, order in (("mainline", list(range(10, 20))), ("full", list(range(20)))):
                frame = context_frame(oracle, tables, order)
                self.assertEqual(oracle.check_context(frame, policy)["message_count"], len(order))
                mutations = {
                    "order": lambda value: value["data"]["messages"].reverse(),
                    "membership": lambda value: value["data"]["messages"].pop(),
                    "evidence": lambda value: value["data"]["evidence"][0].update(byte_start=999),
                    "occurrence": lambda value: value["data"]["evidence"][0].update(occurrence_id="plc_wrong"),
                    "leaf": lambda value: value["data"].update(branch_leaf="msg_v1_wrong"),
                    "level": lambda value: value["data"].update(effective_level="summary"),
                    "partial": lambda value: value.update(outcome="partial"),
                    "truncation": lambda value: value["data"]["truncation"].update(truncated=True),
                    "truncation_reason": lambda value: value["data"]["truncation"].update(reason="byte_budget"),
                    "embedded_session": lambda value: value["data"]["session"]["messages"].pop(),
                    "activities": lambda value: value["data"].update(tool_activities=[{}]),
                }
                for name, mutate in mutations.items():
                    with self.subTest(policy=policy, name=name):
                        bad = copy.deepcopy(frame)
                        mutate(bad)
                        with self.assertRaises(ValueError):
                            oracle.check_context(bad, policy)


class BaselineBoundaryTests(unittest.TestCase):
    def test_shared_deadline_is_not_reset_and_boundary_limits_are_inclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(BENCHMARK.time, "monotonic_ns", return_value=1_000_000_000) as clock:
            scratch = Path(directory)
            budget = BENCHMARK.SuiteBudget(1_000_000_000, STAMP)
            clock.return_value = 3_600_000_000_000
            self.assertEqual(budget.remaining(), 1.0)
            budget.boundary(scratch, 4096.0)
            with self.assertRaisesRegex(ValueError, "RSS"):
                budget.boundary(scratch, 4096.000001)
            (scratch / "payload").write_bytes(b"123456789")
            with patch.object(BENCHMARK, "SCRATCH_LIMIT", 8), self.assertRaisesRegex(ValueError, "scratch"):
                budget.boundary(scratch, None)
            clock.return_value = 3_601_000_000_000
            with self.assertRaisesRegex(ValueError, "deadline"):
                budget.remaining()

    def test_no_clobber_and_cleanup_require_exact_owned_root_and_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report = root / "report.json"
            BENCHMARK.write_json_new(report, {"kept": True})
            before = report.read_bytes()
            with self.assertRaises(FileExistsError):
                BENCHMARK.write_json_new(report, {"kept": False})
            self.assertEqual(report.read_bytes(), before)
            scratch = root / "owned"
            scratch.mkdir()
            owner = {"root": str(scratch), "suite_id": "fixture-suite", "ordinal": 1}
            marker = scratch / ".baseline-owner.json"
            BENCHMARK.write_json_new(marker, owner)
            for invalid in ({**owner, "root": str(root)}, {**owner, "ordinal": 2}):
                with self.assertRaises(ValueError):
                    BENCHMARK.cleanup_scratch(scratch, invalid)
                self.assertTrue(marker.is_file())
            BENCHMARK.cleanup_scratch(scratch, owner)
            self.assertFalse(scratch.exists())
            self.assertEqual(report.read_bytes(), before)

    def test_windows_launch_limit_counts_utf16_and_terminator(self) -> None:
        with patch.object(BENCHMARK.os, "name", "nt"):
            BENCHMARK.launch_size_check(["x" * 32766], {})
            with self.assertRaisesRegex(ValueError, "command-line limit"):
                BENCHMARK.launch_size_check(["x" * 32767], {})
            BENCHMARK.launch_size_check(["\U0001f680" * 16383], {})
            with self.assertRaises(ValueError):
                BENCHMARK.launch_size_check(["\U0001f680" * 16384], {})

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_literals(self) -> None:
        for text in ('{"count":1,"count":2}', '{"v":NaN}', '{"v":Infinity}', '{"v":-Infinity}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                BENCHMARK.strict_json(text)


class SourceAndBuildTests(unittest.TestCase):
    def test_source_requires_clean_exact_harness_and_manifest_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = root / BENCHMARK.HARNESS_PATH
            harness.parent.mkdir(parents=True)
            harness.write_bytes(b"synthetic harness")
            (root / "Cargo.lock").write_bytes(b"synthetic lock")
            (root / "Cargo.toml").write_bytes(b"synthetic manifest")
            outputs = {
                ("git", "rev-parse", "--show-toplevel"): str(root),
                ("git", "rev-parse", "HEAD"): "1" * 40,
                ("git", "status", "--porcelain=v1", "--untracked-files=all"): "",
                ("git", "remote", "get-url", "origin"): "https://github.com/Lain-in-coding/agent-session-grep.git",
                ("git", "ls-files", "--", BENCHMARK.HARNESS_PATH, "Cargo.lock", "Cargo.toml"):
                    BENCHMARK.HARNESS_PATH + "\nCargo.lock\nCargo.toml",
            }
            with patch.object(BENCHMARK, "__file__", str(harness)), \
                 patch.object(BENCHMARK, "checked_command", side_effect=lambda command, cwd: outputs[tuple(command)]):
                receipt = BENCHMARK.source_identity(root, "1" * 40)
                self.assertEqual(receipt["harness_sha256"], hashlib.sha256(b"synthetic harness").hexdigest())
                self.assertEqual(receipt["commit"], receipt["checker_commit"])
                self.assertEqual(receipt["cleanliness"], {"tracked": "clean", "index": "clean", "untracked": "clean"})
                with self.assertRaisesRegex(ValueError, "HEAD differs"):
                    BENCHMARK.source_identity(root, "2" * 40)
                key = ("git", "status", "--porcelain=v1", "--untracked-files=all")
                for dirty in (" M Cargo.toml", "M  Cargo.toml", "?? untracked.py"):
                    outputs[key] = dirty
                    with self.subTest(dirty=dirty), self.assertRaisesRegex(ValueError, "dirty"):
                        BENCHMARK.source_identity(root, "1" * 40)
                outputs[key] = ""
                with patch.object(BENCHMARK, "__file__", str(root / "different.py")), \
                     self.assertRaisesRegex(ValueError, "harness must execute"):
                    BENCHMARK.source_identity(root, "1" * 40)

    def test_build_configuration_rejects_unproved_overrides_without_changing_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cargo, rustc = root / "cargo.exe", root / "rustc.exe"
            cargo.write_bytes(b"cargo fixture")
            rustc.write_bytes(b"rustc fixture")
            args = argparse.Namespace(cargo=str(cargo), rustc=str(rustc))
            environment = {"CARGO_HOME": str(root / "cargo-home"), "CARGO_BUILD_JOBS": "2",
                           "CARGO_TARGET_DIR": str(root / "build-output")}
            with patch.dict(os.environ, environment, clear=True), \
                 patch.object(Path, "home", return_value=root), \
                 patch.object(Path, "exists", return_value=False), \
                 patch.object(BENCHMARK.shutil, "which", side_effect=lambda name: {"cargo": str(cargo), "rustc": str(rustc)}.get(name, name)), \
                 patch.object(BENCHMARK, "checked_command", return_value="rustc 1.97.1\nhost: x86_64-pc-windows-msvc"):
                before = dict(os.environ)
                config, target, _ = BENCHMARK.build_configuration(root, args)
                self.assertEqual(dict(os.environ), before)
                self.assertEqual(target, root / "build-output")
                self.assertEqual(config["environment"]["CARGO_TARGET_DIR"], "explicit-build-target")
                self.assertNotIn(str(root), json.dumps(config))
                for variable in ("RUSTFLAGS", "LIBSQLITE3_SYS_USE_PKG_CONFIG", "CFLAGS",
                                 "SQLCIPHER_LIB_DIR", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "SQLITE_MAX_LENGTH"):
                    with self.subTest(variable=variable), patch.dict(os.environ, {variable: "override"}), \
                         self.assertRaisesRegex(ValueError, "override"):
                        BENCHMARK.build_configuration(root, args)
                with patch.dict(os.environ, {"RUSTFLAGS": ""}), self.assertRaisesRegex(ValueError, "override"):
                    BENCHMARK.build_configuration(root, args)
                with patch.dict(os.environ, {"CARGO_BUILD_TARGET": "different-native-target"}), \
                     self.assertRaisesRegex(ValueError, "native target"):
                    BENCHMARK.build_configuration(root, args)
                with patch.object(Path, "exists", return_value=True), \
                     self.assertRaisesRegex(ValueError, "Cargo configuration"):
                    BENCHMARK.build_configuration(root, args)

    def test_locked_archive_proof_binds_exact_source_bytes_and_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = "libsqlite3-sys-0.38.2"
            source = root / "registry/src/synthetic-registry" / prefix
            source.mkdir(parents=True)
            archive = root / "registry/cache/synthetic-registry" / (prefix + ".crate")
            archive.parent.mkdir(parents=True)
            contents = {"sqlite3/sqlite3.h": b'#define SQLITE_VERSION "3.53.2"\n',
                        "sqlite3/sqlite3.c": b'#define SQLITE_VERSION "3.53.2"\n',
                        "build.rs": b"fn main() {}\n"}
            with tarfile.open(archive, "w:gz") as handle:
                for name, content in contents.items():
                    target = source / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
                    member = tarfile.TarInfo(prefix + "/" + name)
                    member.size = len(content)
                    handle.addfile(member, io.BytesIO(content))
            locked = {"name": "libsqlite3-sys", "version": "0.38.2",
                      "checksum": BENCHMARK.sha256_file(archive),
                      "source": "registry+https://github.com/rust-lang/crates.io-index"}
            package = {"version": "0.38.2", "source": locked["source"],
                       "manifest_path": str(source / "Cargo.toml")}
            proof = BENCHMARK.sqlite_source_proof(package, locked, root)
            self.assertEqual(proof["sqlite_version"], "3.53.2")
            self.assertEqual(proof["header_sha256"], hashlib.sha256(contents["sqlite3/sqlite3.h"]).hexdigest())
            self.assertEqual(proof["method"], "locked-bundled-source-and-build-linkage")
            self.assertIs(proof["runtime_query"], False)
            with self.assertRaisesRegex(ValueError, "Cargo.lock"):
                BENCHMARK.sqlite_source_proof({**package, "version": "0.38.1"}, locked, root)
            (source / "sqlite3/sqlite3.c").write_bytes(b"changed source")
            with self.assertRaisesRegex(ValueError, "differs from locked archive"):
                BENCHMARK.sqlite_source_proof(package, locked, root)
            (source / "sqlite3/sqlite3.c").write_bytes(contents["sqlite3/sqlite3.c"])
            with self.assertRaisesRegex(ValueError, "archive"):
                BENCHMARK.sqlite_source_proof(package, {**locked, "checksum": "0" * 64}, root)

    def test_build_receipt_accepts_identical_msvc_static_library_aliases(self) -> None:
        content = b"synthetic static SQLite library"
        with tempfile.TemporaryDirectory() as directory:
            receipt = build_receipt_from_artifacts(
                Path(directory).resolve(), "x86_64-pc-windows-msvc",
                {"sqlite3.lib": content, "libsqlite3.a": content})
        self.assertEqual(receipt["sqlite"]["native_library_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(receipt["sqlite"]["native_library_size_bytes"], len(content))
        self.assertEqual(receipt["sqlite"]["linked_libraries"], ["static=sqlite3"])
        self.assertEqual(set(receipt["sqlite"]), set(build_receipt()["sqlite"]))

    def test_build_receipt_selects_native_static_library_for_target(self) -> None:
        content = b"synthetic static SQLite library"
        cases = (
            ("x86_64-pc-windows-msvc", {"sqlite3.lib": content}),
            ("aarch64-pc-windows-msvc", {"sqlite3.lib": content, "libsqlite3.a": content}),
            ("x86_64-unknown-linux-gnu", {"libsqlite3.a": content}),
            ("aarch64-apple-darwin", {"libsqlite3.a": content, "sqlite3.lib": content}),
            ("x86_64-pc-windows-gnu", {"libsqlite3.a": content}),
        )
        for target, libraries in cases:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                receipt = build_receipt_from_artifacts(root, target, libraries)
                native = "sqlite3.lib" if target.endswith("-msvc") else "libsqlite3.a"
                self.assertEqual(BENCHMARK.bundled_sqlite_library(root / "target/release/build/sqlite/out", target).name, native)
                self.assertEqual(receipt["sqlite"]["native_library_sha256"], hashlib.sha256(content).hexdigest())

    def test_build_receipt_rejects_missing_native_conflicting_alias_or_dynamic_link(self) -> None:
        content, conflict = b"static A", b"static B"
        cases = (
            ("x86_64-pc-windows-msvc", {}, None, "target-native"),
            ("x86_64-pc-windows-msvc", {"libsqlite3.a": content}, None, "target-native"),
            ("x86_64-unknown-linux-gnu", {"sqlite3.lib": content}, None, "target-native"),
            ("x86_64-pc-windows-msvc", {"sqlite3.lib": content, "libsqlite3.a": conflict}, None, "conflicting"),
            ("x86_64-pc-windows-msvc", {"sqlite3.lib": content, "libsqlite3.a": b"larger alias"}, None, "conflicting"),
            ("x86_64-unknown-linux-gnu", {"sqlite3.lib": conflict, "libsqlite3.a": content}, None, "conflicting"),
            ("x86_64-pc-windows-msvc", {"sqlite3.lib": content, "libsqlite3.a": content}, ["dylib=sqlite3"], "exclusively static"),
        )
        for target, libraries, linked, reason in cases:
            with self.subTest(target=target, reason=reason), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, reason):
                    build_receipt_from_artifacts(Path(directory).resolve(), target, libraries, linked)

    def test_receipt_rejects_wrong_source_binary_or_sqlite_linkage(self) -> None:
        source = source_receipt()
        BENCHMARK.validate_build_receipt(build_receipt(), source)
        changes = (
            (("origin_run",), 2), (("origin_run",), True),
            (("binary_sha256",), "bad"), (("binary_size_bytes",), False),
            (("source", "commit"), "2" * 40), (("configuration", "compiler_link_overrides"), "unknown"),
            (("release_profile", "opt_level"), "0"), (("release_profile", "test"), True),
            (("sqlite", "features"), []), (("sqlite", "features"), ["bundled", "sqlcipher"]),
            (("sqlite", "runtime_query"), True), (("sqlite", "method"), "Python sqlite3"),
            (("sqlite", "linked_libraries"), ["sqlite3"]),
            (("sqlite", "native_library_size_bytes"), 0),
        )
        for path, value in changes:
            receipt = build_receipt()
            cursor = receipt
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(ValueError):
                BENCHMARK.validate_build_receipt(receipt, source)

    def test_run_one_builds_before_clock_and_later_runs_only_reuse_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            scratch, suite = root / "scratch", root / "suite"
            scratch.mkdir()
            suite.mkdir()
            binary = suite / ("baseline-cli.exe" if os.name == "nt" else "baseline-cli")
            contents = b"synthetic binary"
            binary.write_bytes(contents)
            source, receipt = source_receipt(), build_receipt(binary=contents)
            environment = baseline_report()["environment"]
            args = argparse.Namespace(expected_commit=source["commit"], baseline_run=1,
                                      suite_id="synthetic-suite", sqlite_version="3.53.2")
            events = []

            def build(*args):
                events.append("build")
                return binary, receipt

            def monotonic():
                self.assertIn("build", events)
                events.append("clock")
                return 1_000_000_000

            with patch.object(BENCHMARK, "source_identity", return_value=source), \
                 patch.object(BENCHMARK, "build_configuration", return_value=(receipt["configuration"], root, root)), \
                 patch.object(BENCHMARK, "environment", side_effect=lambda *args: copy.deepcopy(environment)), \
                 patch.object(BENCHMARK.shutil, "disk_usage", return_value=SimpleNamespace(free=BENCHMARK.SCRATCH_FREE)), \
                 patch.object(BENCHMARK, "build_receipt", side_effect=build) as builder, \
                 patch.object(BENCHMARK.time, "monotonic_ns", side_effect=monotonic), \
                 patch.object(BENCHMARK, "validate_report", side_effect=lambda *unused, **kwargs: {
                     "baseline": {"suite_id": args.suite_id, "run_ordinal": args.baseline_run - 1,
                                  "build_receipt_sha256": BENCHMARK.json_hash(receipt)}}), \
                 patch.object(BENCHMARK, "datetime", wraps=datetime) as frozen_datetime, \
                 patch.object(BENCHMARK, "utc_now", return_value=STAMP):
                frozen_datetime.now.return_value = datetime(2026, 1, 1, tzinfo=timezone.utc)
                first = BENCHMARK.prepare_suite(root, suite / "run-01", scratch, args)
                self.assertEqual(events[0], "build")
                self.assertEqual(first[3].started_ns, 1_000_000_000)
                for run in (2, 3):
                    previous = suite / f"run-{run - 1:02d}"
                    previous.mkdir()
                    previous_report = previous / "core-beta-benchmark-full.json"
                    BENCHMARK.write_json_new(previous_report, {"synthetic_previous_run": run - 1})
                    BENCHMARK.write_json_new(suite / f"run-{run - 1:02d}.claim.json", {
                        "status": "complete", "suite_id": args.suite_id, "ordinal": run - 1,
                        "output_directory": previous.name,
                        "report_sha256": BENCHMARK.sha256_file(previous_report),
                    })
                    args.baseline_run = run
                    reused = BENCHMARK.prepare_suite(root, suite / f"run-{run:02d}", scratch, args)
                    self.assertEqual(reused[0], binary)
                    self.assertEqual(reused[2], receipt)
                    self.assertEqual(reused[3].started_ns, first[3].started_ns)
                builder.assert_called_once()
                binary.write_bytes(b"modified frozen binary")
                with self.assertRaisesRegex(ValueError, "frozen binary"):
                    BENCHMARK.prepare_suite(root, suite / "run-03", scratch, args)
                builder.assert_called_once()
                with self.assertRaisesRegex(ValueError, "run-1 build receipt"):
                    BENCHMARK.prepare_suite(root, root / "empty-suite/run-02", scratch, args)
                builder.assert_called_once()

    def test_failed_run_retains_successes_failure_phase_and_refuses_retry_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output, scratch = root / "evidence-output/suite/run-01", root / "owned-scratch"
            scratch.mkdir()
            args = argparse.Namespace(profile="full", baseline_run=1, suite_id="synthetic-suite",
                                      expected_commit="1" * 40, binary=None, workspace=str(root),
                                      output_dir=str(output), disk="synthetic NVMe", filesystem="NTFS",
                                      antivirus_state="enabled", sqlite_version="3.53.2",
                                      sqlite_version_source="synthetic fixture")
            budget = Mock()
            budget.elapsed_ms.return_value = 0.0
            budget.remaining.return_value = 3600.0

            def fail_preflight(context):
                context.preflight["observations"] = [{"ordinal": 1, "outcome": "success"},
                                                     {"ordinal": 2, "outcome": "oracle_mismatch"}]
                context.failed_phase = "preflight/intact/search"
                raise ValueError("baseline: synthetic correctness mismatch")

            with patch.object(BENCHMARK.tempfile, "mkdtemp", return_value=str(scratch)), \
                 patch.object(BENCHMARK, "prepare_suite", return_value=(root / "cli", source_receipt(),
                                                                       build_receipt(), budget, {})), \
                 patch.object(BENCHMARK.BaselineRun, "run_preflight", autospec=True, side_effect=fail_preflight), \
                 self.assertRaisesRegex(ValueError, "incomplete attempt retained"):
                BENCHMARK.run_baseline(args)
            attempt_path = output / "attempt.json"
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            self.assertEqual(attempt["status"], "failed")
            self.assertEqual(attempt["failed_phase"], "preflight/intact/search")
            self.assertEqual([entry["outcome"] for entry in attempt["sections"][0]["observations"]],
                             ["success", "oracle_mismatch"])
            self.assertTrue(scratch.exists())
            self.assertFalse((output / "core-beta-benchmark-full.json").exists())
            before = attempt_path.read_bytes()
            with self.assertRaisesRegex(ValueError, "no clobber"):
                BENCHMARK.run_baseline(args)
            self.assertEqual(attempt_path.read_bytes(), before)


class BaselineReportValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.valid = baseline_report()

    def setUp(self) -> None:
        self.corpus = patch.object(BENCHMARK, "corpus_identity", side_effect=mock_corpus_identity)
        self.corpus.start()
        self.addCleanup(self.corpus.stop)

    def validate(self, report: dict) -> dict:
        return BENCHMARK.validate_report(ROOT / "synthetic-report.json", report_data=report, quiet=True)

    def assert_invalid(self, path: tuple, value) -> None:
        report = copy.deepcopy(self.valid)
        cursor = report
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = value
        with self.assertRaises(ValueError) as error:
            self.validate(report)
        self.assertLess(len(str(error.exception)), 250)

    def test_historical_full_and_legacy_only_smoke_remain_valid(self) -> None:
        historical = BENCHMARK.validate_report(HISTORICAL_REPORT, "full", quiet=True)
        self.assertNotIn("baseline", historical)
        smoke = copy.deepcopy(historical)
        smoke["profile"] = "smoke"
        smoke["dataset"].update(file_count=2, message_count=24)
        for name, metric in smoke["metrics"].items():
            count = 3 if "startup" in name else 1 if ("sync" in name or "throughput" in name) else 5
            values, peaks = metric["raw_samples"][:count], metric["peak_rss_mb_raw_samples"][:count]
            metric.update(required_sample_count=count, raw_samples=values,
                          summary=BENCHMARK.rounded_summary(values), peak_rss_mb_raw_samples=peaks,
                          peak_rss_mb_summary=BENCHMARK.rounded_summary(peaks) if peaks else None)
        peaks = [value for metric in smoke["metrics"].values() for value in metric["peak_rss_mb_raw_samples"]]
        smoke["aggregate_peak_rss_mb"] = {"raw_samples": peaks, "summary": BENCHMARK.rounded_summary(peaks) if peaks else None}
        smoke["sizes"]["initial_store_bytes_raw_samples"] = smoke["sizes"]["initial_store_bytes_raw_samples"][:1]
        self.assertEqual(self.validate(smoke)["profile"], "smoke")

    def test_legacy_profile_metric_set_and_sample_count_failures_remain_rejected(self) -> None:
        historical = json.loads(HISTORICAL_REPORT.read_text(encoding="utf-8"))
        cases = [copy.deepcopy(historical) for _ in range(3)]
        cases[0]["profile"] = "unsupported"
        cases[1]["metrics"].pop("get_latency_ms")
        cases[2]["metrics"]["search_latency_ms"]["raw_samples"].pop()
        for report in cases:
            with self.subTest(profile=report["profile"]), self.assertRaises(ValueError):
                self.validate(report)

    def test_valid_extension_roundtrip_and_markdown_use_same_raw_report(self) -> None:
        report = json.loads(json.dumps(self.valid, ensure_ascii=False, allow_nan=False))
        before = copy.deepcopy(report)
        self.assertIs(self.validate(report), report)
        markdown = BENCHMARK.render_markdown(report)
        self.assertEqual(markdown, BENCHMARK.render_markdown(self.valid))
        self.assertIn("process-wall-before-observer/v1", markdown)
        self.assertIn("legacy-wall-with-observer/v1", markdown)
        self.assertIn("SQLite build-derived version", markdown)
        self.assertIn("| `scale-50000` | `context/mainline` | 100 | 2.000 |", markdown)
        self.assertEqual(report, before)

    def test_fixed_matrix_has_exact_warmups_counts_order_and_entity_selection(self) -> None:
        baseline = self.valid["baseline"]
        self.assertEqual(len(baseline["preflight"]["observations"]), 8)
        self.assertEqual(len(baseline["anchor"]["observations"]), 353)
        for section in baseline["workloads"]:
            records = section["observations"]
            self.assertEqual(len(records), 936)
            sync = [record for record in records if record["operation"] == "sync"]
            self.assertEqual([(record["trial"], record["phase"]) for record in sync],
                             [(trial, phase) for trial in (1, 2, 3) for phase in ("initial", "noop", "shrink")])
            self.assertEqual((records[-1]["operation"], records[-1]["phase"], records[-1]["trial"]),
                             ("sync", "shrink", 3))
            search = [record for record in records if record["operation"] == "search"]
            self.assertEqual([record["role"] for record in search[:15]], ["warmup"] * 15)
            self.assertEqual([record["query_class"] for record in search[15:]],
                             ["token", "latin", "cjk", "path", "identifier"] * 100)
            for operation in ("show", "get", "context"):
                selected = [record for record in records if record["operation"] == operation]
                self.assertEqual(len(selected), 206 if operation == "context" else 103)
        middle = next(section for section in baseline["workloads"] if section["id"] == "scale-10000")
        self.assertEqual(middle["retrieval_indices"], [file * 200 + local for local in (0, 1) for file in range(50)])

    def test_extension_version_and_closed_container_shapes(self) -> None:
        cases = [
            (("baseline",), value) for value in (None, [], "invalid", True)
        ] + [
            (("baseline", "schema_version"), "agent-session-grep.current-source-baseline/v2"),
            (("baseline", "plan"), []), (("baseline", "source_before"), []),
            (("baseline", "build_receipt"), "invalid"), (("baseline", "workloads"), {}),
            (("baseline", "coverage"), None), (("baseline", "preflight"), []),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_invalid(path, value)
        for key in ("plan", "coverage", "source_after", "build_receipt_sha256"):
            report = copy.deepcopy(self.valid)
            report["baseline"].pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validate(report)
        report = copy.deepcopy(self.valid)
        report["baseline"]["unrecognized"] = 1
        with self.assertRaises(ValueError):
            self.validate(report)

    def test_numeric_fields_reject_booleans_nonfinite_negative_and_wrong_types(self) -> None:
        base = ("baseline", "workloads", 0, "observations", 0)
        for value in (True, -1, float("nan"), float("inf"), "2", [], {}):
            with self.subTest(value=value):
                self.assert_invalid((*base, "process_wall_ms"), value)
        cases = [
            ((*base, "ordinal"), True), ((*base, "trial"), True),
            ((*base, "stdout_bytes"), True), ((*base, "stdout_bytes"), 0),
            ((*base, "cli_reported_duration_ms"), 1.5),
            ((*base, "memory", "observation_count"), True),
            ((*base, "memory", "interval_ms"), True),
            ((*base, "memory", "peak_rss_mib"), False),
            (("baseline", "run_ordinal"), True),
            (("baseline", "suite_started_monotonic_ns"), False),
            (("baseline", "completed_elapsed_ms"), 3600001),
            ((*base, "process_wall_ms"), 3.000001),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_invalid(path, value)

    def test_workloads_phases_counts_and_query_contracts_are_closed(self) -> None:
        base = ("baseline", "workloads", 0)
        cases = [
            (("baseline", "workloads"), self.valid["baseline"]["workloads"][:2]),
            (("baseline", "workloads", 1), self.valid["baseline"]["workloads"][0]),
            ((*base, "id"), "scale-50001"), ((*base, "file_count"), 11),
            ((*base, "messages_per_file"), 201), ((*base, "query_phase"), "post_shrink"),
            ((*base, "query_trial"), 2), ((*base, "observations"), []),
            ((*base, "observations", 8, "role"), "measured"),
            ((*base, "observations", 8, "query_class"), "unsupported"),
            ((*base, "observations", 0, "sample_index"), 2),
            (("baseline", "plan", "timing_protocol"), "legacy-wall-with-observer/v1"),
            (("baseline", "plan", "query_warmups"), 0),
            (("baseline", "plan", "scale_order"), ["scale-50000", "scale-10000", "scale-2000"]),
            ((*base, "retrieval_indices", 0), 1),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_invalid(path, value)
        report = copy.deepcopy(self.valid)
        report["baseline"]["workloads"][0]["observations"].append(
            copy.deepcopy(report["baseline"]["workloads"][0]["observations"][-1]))
        with self.assertRaisesRegex(ValueError, "coverage"):
            self.validate(report)

    def test_corpus_census_store_and_noop_binding_must_match_phase(self) -> None:
        base = ("baseline", "workloads", 0, "snapshots", 0)
        cases = [
            ((*base, "phase"), "noop"), ((*base, "trial"), 2),
            ((*base, "corpus", "source_occurrences"), 1999),
            ((*base, "corpus", "source_bytes"), 0),
            ((*base, "corpus", "tree_hash"), "0" * 64),
            ((*base, "census", "generation"), 2), ((*base, "census", "messages"), 1999),
            ((*base, "census", "placements"), True), ((*base, "census", "removed_verified"), 1),
            ((*base, "store", "total_bytes"), 4096),
            ((*base, "store", "files", 0, "bytes"), True),
            ((*base, "store", "files", 1, "name"), "catalog.db"),
            ((*base, "store", "coverage"), "checkpointed"),
            (("baseline", "workloads", 0, "snapshots", 1, "census", "bindings_sha256"), "0" * 64),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_invalid(path, value)
        snapshots = self.valid["baseline"]["workloads"][0]["snapshots"]
        self.assertNotEqual(snapshots[0]["census"]["bindings_sha256"], snapshots[3]["census"]["bindings_sha256"])
        self.validate(self.valid)

    def test_context_anchor_graph_membership_and_evidence_are_bound(self) -> None:
        base = ("baseline", "workloads", 0, "context_anchor")
        cases = [
            ((*base, "generator_file"), 1), ((*base, "source_sha256"), "0" * 64),
            ((*base, "session_id"), "ses_v1_bad"), ((*base, "members"), []),
            ((*base, "members", 1, "generator_index"), 0),
            ((*base, "members", 1, "byte_start"), 0),
            ((*base, "members", 1, "placement_id"), "plc_v1_" + "0" * 32),
            ((*base, "mainline_order"), list(range(10))),
            ((*base, "full_order"), list(range(200))),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_invalid(path, value)

    def test_success_memory_alignment_and_raw_derived_summaries_are_required(self) -> None:
        base = ("baseline", "workloads", 0)
        cases = [
            ((*base, "observations", 0, "exit_code"), 10),
            ((*base, "observations", 0, "outcome"), "partial"),
            ((*base, "observations", 0, "correctness", "committed"), 0),
            ((*base, "observations", 0, "memory", "unavailable_reason"), "invented"),
            ((*base, "observations", 0, "memory", "method"), "virtual_memory"),
            ((*base, "summaries", "sync/initial", "process_wall_ms", "mad"), 1.0),
            ((*base, "summaries", "sync/initial", "process_wall_ms", "p50"), 1.0),
            ((*base, "summaries", "sync/initial", "memory_available_count"), 100),
            ((*base, "derived", "initial_messages_per_second", "raw_samples", 0), 0.0),
            ((*base, "derived", "store_source_ratios", 0, "ratio"), 0.0),
            (("baseline", "coverage", "complete"), False),
            (("baseline", "coverage", "failed_observations"), 1),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_invalid(path, value)

    def test_anchor_links_reject_independently_valid_legacy_sample_tampering(self) -> None:
        report = copy.deepcopy(self.valid)
        metric = report["metrics"]["show_latency_ms"]
        metric["raw_samples"][0] = 4.0
        metric["summary"] = BENCHMARK.rounded_summary(metric["raw_samples"])
        legacy = copy.deepcopy(report)
        legacy.pop("baseline")
        self.validate(legacy)
        with self.assertRaisesRegex(ValueError, "invocation link"):
            self.validate(report)

    def test_source_build_environment_and_prebuilt_labels_cannot_be_rewritten(self) -> None:
        cases = [
            (("baseline", "source_before", "checker_commit"), "2" * 40),
            (("baseline", "source_after", "harness_sha256"), "0" * 64),
            (("baseline", "source_before", "cleanliness", "index"), "dirty"),
            (("baseline", "build_receipt_sha256"), "0" * 64),
            (("baseline", "binary_use"), "reused_run_1_receipt"),
            (("baseline", "child_policy", "trace"), "inherited"),
            (("environment", "sqlite_version_source"), "Python sqlite3"),
            (("environment", "target_triple"), "x86_64-unknown-linux-gnu"),
            (("binary", "binary_hash"), "0" * 64),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.assert_invalid(path, value)
        second = baseline_report(2)
        self.validate(second)
        second["binary"]["provenance"] = "built_by_harness_from_workspace"
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.validate(second)
        second["binary"]["provenance"] = "caller_supplied_prebuilt"
        second["limitations"] = ["No independent statement."]
        with self.assertRaisesRegex(ValueError, "attest"):
            self.validate(second)

    def test_public_extension_rejects_unowned_paths_and_overlapping_intervals(self) -> None:
        base = ("baseline", "workloads", 0, "observations", 0)
        private_path = str(Path(tempfile.gettempdir()).resolve() / "synthetic-private-location")
        self.assert_invalid((*base, "argv", 0), private_path)
        previous_end = self.valid["baseline"]["anchor"]["observations"][-1]["completed_at_utc"]
        self.assert_invalid((*base, "started_at_utc"), STAMP)
        self.assertNotEqual(previous_end, STAMP)


class BaselineSuiteValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reports = [baseline_report(run) for run in (1, 2, 3)]

    def setUp(self) -> None:
        self.corpus = patch.object(BENCHMARK, "corpus_identity", side_effect=mock_corpus_identity)
        self.corpus.start()
        self.addCleanup(self.corpus.stop)

    def write_reports(self, root: Path, reports: list[dict]) -> list[Path]:
        paths = [root / f"report-{index}.json" for index in range(len(reports))]
        for path, report in zip(paths, reports):
            path.write_text(json.dumps(report, ensure_ascii=False, allow_nan=False), encoding="utf-8")
        return paths

    def test_three_reports_validate_in_any_input_order_and_recompute_spread(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new_callable=io.StringIO):
            paths = self.write_reports(Path(directory), self.reports)
            result = BENCHMARK.validate_baseline(reversed(paths))
        self.assertEqual(result["run_count"], 3)
        self.assertEqual(result["source_commit"], "1" * 40)
        self.assertEqual(len(result["comparison"]), 48)
        entry = result["comparison"]["scale-50000/context/mainline"]
        self.assertEqual(entry["run_p50_ms"], [2.0, 2.0, 2.0])
        self.assertEqual(entry["spread_percent"], 0.0)
        self.assertIs(entry["noise_warning"], False)

    def test_suite_rejects_missing_duplicate_and_legacy_only_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new_callable=io.StringIO):
            root = Path(directory)
            paths = self.write_reports(root, self.reports)
            for invalid in (paths[:2], [paths[0]] * 3):
                with self.subTest(paths=invalid), self.assertRaises(ValueError):
                    BENCHMARK.validate_baseline(invalid)
            paths = self.write_reports(root, [self.reports[0]] * 3)
            with self.assertRaisesRegex(ValueError, "duplicate reports"):
                BENCHMARK.validate_baseline(paths)
            historical = json.loads(HISTORICAL_REPORT.read_text(encoding="utf-8"))
            paths = self.write_reports(root, [historical] * 3)
            with self.assertRaisesRegex(ValueError, "legacy-only"):
                BENCHMARK.validate_baseline(paths)

    def test_suite_rejects_changed_identity_environment_ordinal_and_overlap(self) -> None:
        mutations = {
            "suite": lambda reports: reports[1]["baseline"].update(suite_id="different-suite"),
            "environment": lambda reports: reports[1]["environment"].update(disk="different synthetic disk"),
            "elapsed_overlap": lambda reports: reports[1]["baseline"].update(started_elapsed_ms=1.0),
            "duplicate_ordinal": lambda reports: reports.__setitem__(2, copy.deepcopy(reports[1])),
        }
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdout", new_callable=io.StringIO):
            root = Path(directory)
            for name, mutate in mutations.items():
                reports = copy.deepcopy(self.reports)
                mutate(reports)
                reports[2]["generated_at_utc"] = "2026-01-01T00:03:00Z"
                paths = self.write_reports(root, reports)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    BENCHMARK.validate_baseline(paths)


if __name__ == "__main__":
    unittest.main()
