"""Synthetic child-only tests. Never discover or run installed actual hosts."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

MODULE_PATH = Path(__file__).with_name("beta-host-evaluation.py")
SPEC = importlib.util.spec_from_file_location("beta_host_evaluation", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def jsonl(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def header_frame(value: dict) -> bytes:
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\nContent-Type: application/json\r\n\r\n" + body


def fallback_metadata(model: str) -> str:
    """Exact codex-cli 0.166.0 warning text, kept independent of the module under test."""
    return ("Model metadata for `" + model + "` not found. Defaulting to fallback metadata; "
            "this can degrade performance and cause issues.")


class CaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="asg-host-capture-test-")
        self.root = Path(self.temporary.name).resolve()
        self.profile = self.root / "profile"
        self.work = self.root / "work"
        self.out = self.root / "out"
        for path in (self.profile, self.work, self.out):
            path.mkdir()
        self.executable = Path(sys.executable).resolve()
        self.executable_sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def child(self, source: str) -> list[str]:
        path = self.work / ("child-" + str(len(list(self.work.glob("child-*.py")))) + ".py")
        path.write_text(source, encoding="utf-8")
        return [str(self.executable), "-u", str(path)]

    def host(self, host: str, source: str, run_id: str = "run", **kwargs) -> dict:
        return RUNNER.run_host(host, self.child(source), profile_dir=self.profile,
                               workdir=self.work, prompt="历史 query\u2028保持原文\n".encode(),
                               output_root=self.out, run_id=run_id, timeout_seconds=kwargs.pop("timeout_seconds", 3),
                               cleanup_seconds=kwargs.pop("cleanup_seconds", 1), **kwargs)

    def proxy(self, source: str, input_bytes: bytes, run_id: str = "proxy", **kwargs) -> tuple[dict, bytes]:
        input_path = self.work / (run_id + "-input.bin")
        output_path = self.work / (run_id + "-output.bin")
        input_path.write_bytes(input_bytes)
        with input_path.open("rb", buffering=0) as input_handle, output_path.open("wb", buffering=0) as output_handle:
            result = RUNNER.proxy_stdio(self.child(source), expected_executable_sha256=self.executable_sha,
                                        workdir=self.work, output_root=self.out, run_id=run_id,
                                        timeout_seconds=kwargs.pop("timeout_seconds", 3),
                                        input_stream=input_handle, output_stream=output_handle, **kwargs)
        return result, output_path.read_bytes()

    def test_native_claude_regular_output_and_usage(self) -> None:
        result = self.host("claude-code", """import sys,json,os
from pathlib import Path
prompt=sys.stdin.buffer.read()
Path("received.private.json").write_text(json.dumps({"argv":sys.argv[1:],"prompt_sha":__import__("hashlib").sha256(prompt).hexdigest(),"profile":os.environ.get("CLAUDE_CONFIG_DIR")}),encoding="utf-8")
for event in [
 {"type":"system","subtype":"init","session_id":"synthetic-session","model":"synthetic-model","claude_code_version":"synthetic-v1"},
 {"type":"assistant","message":{"usage":{"input_tokens":999},"content":[{"type":"tool_use","id":"call1","name":"mcp__agent-session-grep__search_sessions","input":{"query":"合成"}}]}},
 {"type":"result","subtype":"success","is_error":False,"result":"done synthetic","usage":{"input_tokens":41,"output_tokens":7,"cache_read_input_tokens":13,"cache_creation_input_tokens":0},"permission_denials":[]}]:
 sys.stdout.buffer.write(json.dumps(event,ensure_ascii=False).encode("utf-8")+b"\\n")
 sys.stdout.buffer.flush()
""")
        self.assertEqual(result["native_status"], "success")
        self.assertTrue(result["capture_complete"])
        # Claude captures never classify fallback metadata, so they claim no count.
        self.assertIsNone(result["native_fallback_metadata_warning_count"])
        self.assertEqual(result["measurements"]["tokens"]["model_input_tokens"]["value"], 41)
        self.assertEqual(result["measurements"]["tokens"]["model_input_tokens"]["coverage"], "full-evaluation-episode")
        self.assertEqual(result["measurements"]["tokens"]["model_cache_write_tokens"]["value"], 0)
        self.assertEqual(result["measurements"]["tokens"]["model_total_tokens"]["status"], "unavailable")
        self.assertEqual(result["measurements"]["transport"]["asg_total_bytes"]["status"], "unavailable")
        self.assertEqual(result["asg_trace"][0]["operation_name"], "search_sessions")
        self.assertEqual(result["asg_trace_completeness"], "partial")
        received = json.loads((self.work / "received.private.json").read_text())
        self.assertEqual(received["profile"], str(self.profile))
        self.assertIn("stream-json", received["argv"])
        self.assertEqual(received["prompt_sha"], result["prompt_sha256"])
        self.assertNotIn(str(self.profile), json.dumps(result))
        self.assertNotIn("合成", json.dumps(result, ensure_ascii=False))
        self.assertIn("合成".encode("utf-8"), (self.out / "run" / "stdout.private.jsonl").read_bytes())

    def test_codex_usage_and_start_complete_dedup(self) -> None:
        result = self.host("codex", """import sys,json,os
from pathlib import Path
sys.stdin.buffer.read()
Path("received.private.json").write_text(json.dumps({"argv":sys.argv[1:],"profile":os.environ.get("CODEX_HOME")}),encoding="utf-8")
for event in [
 {"type":"thread.started","thread_id":"synthetic-thread"},
 {"type":"item.started","item":{"id":"call1","type":"mcp_tool_call","server":"agent-session-grep","tool":"get_message","arguments":{"id":"msg_v1_synthetic"},"status":"in_progress"}},
 {"type":"item.completed","item":{"id":"call1","type":"mcp_tool_call","server":"agent-session-grep","tool":"get_message","status":"completed"}},
 {"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"done synthetic"}},
 {"type":"turn.completed","usage":{"input_tokens":40,"cached_input_tokens":30,"output_tokens":5}}]:
 print(json.dumps(event),flush=True)
""")
        self.assertEqual(result["native_status"], "turn.completed")
        self.assertEqual(len(result["asg_trace"]), 1)
        self.assertEqual(result["measurements"]["tokens"]["model_input_tokens"]["value"], 40)
        self.assertEqual(result["measurements"]["tokens"]["model_cache_read_tokens"]["value"], 30)
        self.assertEqual(result["measurements"]["tokens"]["model_cache_write_tokens"]["status"], "unavailable")
        self.assertEqual(result["measurements"]["tokens"]["model_total_tokens"]["status"], "unavailable")
        self.assertTrue(result["capture_complete"])
        # Clean stdout still lacks independent evidence attributing usage to this turn.
        for metric in result["measurements"]["tokens"].values():
            if metric["status"] == "observed":
                self.assertEqual(metric["coverage"], "partial-episode")
                self.assertIn("stdout-thread-cumulative", metric["method"])
        received = json.loads((self.work / "received.private.json").read_text())
        self.assertEqual(received["argv"][:2], ["exec", "--json"])
        self.assertEqual(received["argv"][-1], "-")
        self.assertEqual(received["profile"], str(self.profile))

    def test_codex_resumed_usage_keeps_cumulative_counters_without_episode_coverage(self) -> None:
        thread_id = hashlib.sha256(b"synthetic-seeded-thread").hexdigest()
        seed = {"input_tokens": 17, "output_tokens": 3, "cached_input_tokens": 5,
                "cache_write_input_tokens": 2, "total_tokens": 20}
        # The resumed snapshot includes the nonzero seed; it is not a turn delta.
        resumed = {"input_tokens": 46, "output_tokens": 9, "cached_input_tokens": 11,
                   "cache_write_input_tokens": 6, "total_tokens": 55}
        expected = {"model_input_tokens": 46, "model_output_tokens": 9,
                    "model_cache_read_tokens": 11, "model_cache_write_tokens": 6,
                    "model_total_tokens": 55}
        for label, rows in (("resume-only", [resumed]), ("seed-and-resume", [seed, resumed]),
                            ("duplicate-terminal", [seed, resumed, resumed])):
            with self.subTest(capture=label):
                native = RUNNER.NativeEvents("codex", "asg")
                native.feed({"type": "thread.started", "thread_id": thread_id}, 1)
                for ordinal, usage in enumerate(rows, 2):
                    native.feed({"type": "turn.completed", "usage": usage}, ordinal)
                metrics = native.tokens(True)
                self.assertEqual({key: metric["value"] for key, metric in metrics.items()}, expected)
                for metric in metrics.values():
                    self.assertEqual(metric["coverage"], "partial-episode")
                    self.assertIn("stdout-thread-cumulative", metric["method"])
                self.assertEqual(native.session_id, thread_id)

    def test_codex_missing_or_malformed_final_usage_never_reuses_seed(self) -> None:
        for usage in (None, [], True, "synthetic-invalid-usage", {},
                      {"input_tokens": -1}, {"input_tokens": True},
                      {"input_tokens": 1.5}, {"input_tokens": "46"}):
            with self.subTest(usage=usage):
                native = RUNNER.NativeEvents("codex", "asg")
                native.feed({"type": "turn.completed", "usage": {"input_tokens": 17, "output_tokens": 3}}, 1)
                event = {"type": "turn.completed"}
                if usage is not None:
                    event["usage"] = usage
                native.feed(event, 2)
                metrics = native.tokens(True)
                self.assertTrue(all(metric["status"] == "unavailable" for metric in metrics.values()))
                self.assertTrue(all("value" not in metric for metric in metrics.values()))

        native = RUNNER.NativeEvents("codex", "asg")
        native.feed({"type": "turn.completed", "usage": {"input_tokens": 17, "output_tokens": 3}}, 1)
        native.feed({"type": "turn.completed", "usage": {
            "input_tokens": False, "output_tokens": 9, "cached_input_tokens": 0}}, 2)
        metrics = native.tokens(True)
        self.assertEqual(metrics["model_input_tokens"]["status"], "unavailable")
        self.assertEqual(metrics["model_output_tokens"]["value"], 9)
        self.assertEqual(metrics["model_output_tokens"]["coverage"], "partial-episode")
        self.assertEqual(metrics["model_cache_read_tokens"]["value"], 0)
        self.assertEqual(metrics["model_total_tokens"]["status"], "unavailable")

    def test_codex_completed_error_items_deduplicate_by_id_not_text(self) -> None:
        native = RUNNER.NativeEvents("codex", "asg")
        first, second = [hashlib.sha256(f"synthetic-error-{ordinal}".encode()).hexdigest() for ordinal in (1, 2)]
        for kind, item_id, message, expected in (
            ("item.started", first, "synthetic diagnostic", 0),
            ("item.updated", first, "synthetic diagnostic", 0),
            ("item.completed", first, "synthetic diagnostic", 1),
            ("item.completed", first, "changed synthetic diagnostic", 1),
            ("item.completed", second, "synthetic diagnostic", 2),
        ):
            with self.subTest(event=kind, expected=expected):
                native.feed({"type": kind, "item": {"id": item_id, "type": "error", "message": message}}, 1)
                self.assertEqual(native.errors, expected)
        self.assertFalse(native.tool_ids)
        native.feed({"type": "turn.completed"}, 2)
        self.assertEqual(native.terminal, "turn.completed")
        self.assertEqual(native.errors, 2)

    def test_codex_unidentified_completed_errors_cannot_claim_zero(self) -> None:
        native = RUNNER.NativeEvents("codex", "asg")
        for expected, item_id in enumerate((None, "", False, 0, [], {}, "synthetic-" + chr(0xD800)), 1):
            with self.subTest(item_id=item_id):
                item = {"type": "error"}
                if item_id is not None:
                    item["id"] = item_id
                native.feed({"type": "item.completed", "item": item}, expected)
                self.assertEqual(native.errors, expected)

    def test_codex_completed_with_diagnostics_keeps_raw_details_private(self) -> None:
        item_ids = [str(self.work / f"synthetic-error-{ordinal}") for ordinal in (1, 2)]
        diagnostic = "Synthetic diagnostic at " + str(self.work / "synthetic-detail")
        events = [
            {"type": "item.completed", "item": {"id": item_id, "type": "error", "message": diagnostic}}
            for item_id in (item_ids[0], item_ids[0], item_ids[1])
        ] + [
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "synthetic-answer", "type": "agent_message", "text": "done"}},
            {"type": "turn.completed", "usage": {"input_tokens": 46, "output_tokens": 9}},
        ]
        raw = b"".join(jsonl(event) for event in events)
        result = self.host("codex", "import sys\nsys.stdin.buffer.read()\n"
                           f"sys.stdout.buffer.write({raw!r})\nsys.stdout.buffer.flush()\n")
        self.assertEqual(result["native_error_count"], 2)
        self.assertEqual(result["native_fallback_metadata_warning_count"], 0)
        self.assertEqual(result["native_status"], "turn.completed")
        self.assertEqual(result["execution_state"], "completed")
        self.assertEqual(result["native_returncode_before_cleanup"], 0)
        self.assertTrue(result["capture_complete"])
        self.assertEqual(result["acceptance"], "open")
        rendered = json.dumps(result, ensure_ascii=False)
        for private_value in ("Synthetic diagnostic at", "synthetic-error-", "synthetic-detail"):
            self.assertNotIn(private_value, rendered)
        self.assertEqual((self.out / "run" / "stdout.private.jsonl").read_bytes(), raw)

    def test_codex_exact_fallback_metadata_warning_is_recorded_not_counted(self) -> None:
        first, second = [hashlib.sha256(f"synthetic-warning-{ordinal}".encode()).hexdigest() for ordinal in (1, 2)]
        for model in ("synthetic-router/model-1", "synthetic model:2", "合成-模型"):
            with self.subTest(model=model):
                native = RUNNER.NativeEvents("codex", "asg")
                for kind, item_id, warnings in (
                    ("item.started", first, 0), ("item.updated", first, 0),
                    ("item.completed", first, 1), ("item.completed", first, 1),
                    ("item.completed", second, 2), ("item.completed", None, 3),
                ):
                    item = {"type": "error", "message": fallback_metadata(model)}
                    if item_id is not None:
                        item["id"] = item_id
                    native.feed({"type": kind, "item": item}, 1)
                    self.assertEqual((native.errors, native.fallback_metadata_warnings), (0, warnings))
                self.assertFalse(native.tool_ids)
                native.feed({"type": "turn.completed"}, 2)
                self.assertEqual((native.terminal, native.errors), ("turn.completed", 0))

    def test_codex_fallback_metadata_near_misses_remain_errors(self) -> None:
        exact = fallback_metadata("synthetic-router")
        control = RUNNER.NativeEvents("codex", "asg")
        control.feed({"type": "item.completed", "item": {"id": "synthetic-control", "type": "error", "message": exact}}, 1)
        self.assertEqual((control.errors, control.fallback_metadata_warnings), (0, 1))
        near_misses = {
            "changed wording": exact.replace("Defaulting to", "Using"),
            "lowercase prefix": "m" + exact[1:],
            "missing final period": exact[:-1],
            "extra suffix": exact + " Synthetic extra text.",
            "extra prefix": "Synthetic: " + exact,
            "trailing newline": exact + "\n",
            "second message on a new line": exact + "\n" + fallback_metadata("synthetic-other"),
            "concatenated second message": exact + fallback_metadata("synthetic-other"),
            "newline in model": fallback_metadata("synthetic\nrouter"),
            "carriage return in model": fallback_metadata("synthetic\rrouter"),
            "line separator in model": fallback_metadata("synthetic\u2028router"),
            "backtick in model": fallback_metadata("synthetic`router"),
            "empty model": fallback_metadata(""),
            "shared backtick": fallback_metadata("").replace("``", "`"),
        }
        cases = [(label, {"message": message}) for label, message in near_misses.items()]
        cases += [("missing message", {}), ("text field only", {"text": exact})]
        cases += [(f"non-string {type(value).__name__}", {"message": value})
                  for value in (None, [exact], {"message": exact}, 0, True)]
        for label, fields in cases:
            with self.subTest(case=label):
                native = RUNNER.NativeEvents("codex", "asg")
                native.feed({"type": "item.completed", "item": {
                    "id": hashlib.sha256(label.encode()).hexdigest(), "type": "error", **fields}}, 1)
                self.assertEqual((native.errors, native.fallback_metadata_warnings), (1, 0))

    def test_codex_fallback_metadata_tolerance_cannot_hide_other_errors(self) -> None:
        native = RUNNER.NativeEvents("codex", "asg")
        ids = [hashlib.sha256(f"synthetic-item-{ordinal}".encode()).hexdigest() for ordinal in (1, 2, 3)]
        for row, (item_id, message, expected) in enumerate((
            (ids[0], fallback_metadata("synthetic-router"), (0, 1)),
            # A second distinct fallback text in the same capture is not tolerated.
            (ids[1], fallback_metadata("synthetic-other"), (1, 1)),
            (ids[2], fallback_metadata("synthetic-router"), (1, 2)),
            # A warning id cannot hide a later real error with the same id.
            (ids[0], "synthetic real diagnostic", (2, 2)),
            (ids[0], "synthetic real diagnostic", (2, 2)),
        )):
            with self.subTest(row=row):
                native.feed({"type": "item.completed", "item": {"id": item_id, "type": "error", "message": message}}, 1)
                self.assertEqual((native.errors, native.fallback_metadata_warnings), expected)
        native.feed({"type": "error", "message": fallback_metadata("synthetic-router")}, 2)
        self.assertEqual(native.errors, 3)
        native.feed({"type": "turn.failed", "error": {"message": fallback_metadata("synthetic-router")}}, 3)
        self.assertEqual((native.terminal, native.errors, native.fallback_metadata_warnings), ("turn.failed", 4, 2))

    def test_codex_fallback_metadata_warning_summary_count(self) -> None:
        warning = {"type": "item.completed", "item": {"id": "synthetic-warning", "type": "error",
                                                      "message": fallback_metadata("synthetic-router/model")}}
        real_error = {"type": "item.completed", "item": {"id": "synthetic-error", "type": "error",
                                                         "message": "Synthetic real diagnostic"}}
        tail = [
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "synthetic-answer", "type": "agent_message", "text": "done"}},
            {"type": "turn.completed", "usage": {"input_tokens": 46, "output_tokens": 9}},
        ]
        # Consumers fail any capture with a nonzero native_error_count.
        for run_id, events, expected_errors in (("warning-only", [warning], 0),
                                                ("warning-and-error", [warning, real_error], 1)):
            with self.subTest(run=run_id):
                raw = b"".join(jsonl(event) for event in [
                    {"type": "thread.started", "thread_id": "synthetic-thread"}, *events, *tail])
                result = self.host("codex", "import sys\nsys.stdin.buffer.read()\n"
                                   f"sys.stdout.buffer.write({raw!r})\nsys.stdout.buffer.flush()\n", run_id=run_id)
                self.assertEqual(result["native_error_count"], expected_errors)
                self.assertEqual(result["native_fallback_metadata_warning_count"], 1)
                self.assertEqual(result["native_status"], "turn.completed")
                self.assertEqual(result["execution_state"], "completed")
                self.assertTrue(result["capture_complete"])
                self.assertEqual(result["acceptance"], "open")
                rendered = json.dumps(result, ensure_ascii=False)
                for private_value in ("Model metadata", "synthetic-router", "Synthetic real diagnostic"):
                    self.assertNotIn(private_value, rendered)
                self.assertEqual((self.out / run_id / "stdout.private.jsonl").read_bytes(), raw)

    def test_missing_and_malformed_usage_are_unavailable(self) -> None:
        native = RUNNER.NativeEvents("codex", "asg")
        native.feed({"type": "turn.completed", "usage": {"input_tokens": -1, "cached_input_tokens": True}}, 10)
        self.assertTrue(all(metric["status"] == "unavailable" for metric in native.tokens(True).values()))
        native = RUNNER.NativeEvents("claude-code", "asg")
        native.feed({"type": "result", "subtype": "success", "result": "synthetic"}, 10)
        self.assertTrue(all(metric["status"] == "unavailable" for metric in native.tokens(True).values()))

    def test_max_turns_is_not_success(self) -> None:
        result = self.host("claude-code", """import json
print(json.dumps({"type":"result","subtype":"error_max_turns","is_error":True,"num_turns":2,"usage":{"input_tokens":12,"output_tokens":3}}),flush=True)
""")
        self.assertEqual(result["native_status"], "error_max_turns")
        self.assertEqual(result["execution_state"], "failed")
        self.assertIsNone(result["final_response_sha256"])
        self.assertEqual(result["native_error_count"], 1)

    def test_timeout_preserves_partial_events_and_native_exit(self) -> None:
        started = time.monotonic()
        result = self.host("codex", """import json,time
print(json.dumps({"type":"thread.started","thread_id":"synthetic-timeout"}),flush=True)
print(json.dumps({"type":"item.completed","item":{"id":"a","type":"agent_message","text":"partial synthetic answer"}}),flush=True)
time.sleep(30)
""", timeout_seconds=0.35)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertTrue(result["timed_out"])
        self.assertIsNone(result["native_returncode_before_cleanup"])
        self.assertIsNotNone(result["native_returncode_after_cleanup"])
        self.assertFalse(result["capture_complete"])
        self.assertEqual(result["measurements"]["tokens"]["model_input_tokens"]["status"], "unavailable")
        self.assertTrue((self.out / "run" / "stdout.private.jsonl").read_bytes())

    def test_completed_but_stalled_is_distinct(self) -> None:
        started = time.monotonic()
        result = self.host("codex", """import json,time
print(json.dumps({"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"done"}}),flush=True)
print(json.dumps({"type":"turn.completed","usage":{"input_tokens":8,"cached_input_tokens":0,"output_tokens":2}}),flush=True)
time.sleep(30)
""", completion_grace_seconds=0.1)
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(result["completed_but_stalled"])
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["native_status"], "turn.completed")
        self.assertIsNone(result["native_returncode_before_cleanup"])
        self.assertEqual(result["measurements"]["tokens"]["model_input_tokens"]["coverage"], "partial-episode")

    def test_default_completion_grace_does_not_extend_hard_timeout(self) -> None:
        result = self.host("codex", """import json,time
print(json.dumps({"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"done"}}),flush=True)
print(json.dumps({"type":"turn.completed"}),flush=True)
time.sleep(30)
""", timeout_seconds=1)
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["completed_but_stalled"])
        self.assertEqual(result["stop_reason"], "time_budget")
        self.assertEqual(result["native_status"], "turn.completed")
        self.assertFalse(result["capture_complete"])
        self.assertEqual(result["measurements"]["latency"]["end_to_end"]["coverage"], "partial-episode")
        self.assertLess(result["measurements"]["latency"]["end_to_end"]["end_monotonic_ns"],
                        result["stopped_monotonic_ns"])

    def late_observed_exit(self, **kwargs) -> dict:
        class CompletedProcess:
            first_poll = True

            def poll(self):
                if self.first_poll:
                    self.first_poll = False
                    time.sleep(0.25)
                return 0

        def spawn(argv, **kwargs):
            for event in (
                {"type": "item.completed", "item": {"id": "answer", "type": "agent_message", "text": "done"}},
                {"type": "turn.completed"},
            ):
                kwargs["stdout"].write(jsonl(event))
            return CompletedProcess()

        with patch.object(RUNNER.ProcessTree, "spawn", side_effect=spawn), \
             patch.object(RUNNER.ProcessTree, "stop", return_value="complete"):
            return self.host("codex", "raise SystemExit(0)\n", **kwargs)

    def test_host_exit_observed_after_hard_deadline_stays_incomplete(self) -> None:
        result = self.late_observed_exit(timeout_seconds=0.2)
        self.assertEqual(result["native_returncode_before_cleanup"], 0)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["stop_reason"], "time_budget")
        self.assertFalse(result["capture_complete"])
        self.assertEqual(result["execution_state"], "failed")

    def test_host_exit_observed_after_completion_grace_stays_incomplete(self) -> None:
        result = self.late_observed_exit(timeout_seconds=3, completion_grace_seconds=0.1)
        self.assertEqual(result["native_returncode_before_cleanup"], 0)
        self.assertFalse(result["timed_out"])
        self.assertTrue(result["completed_but_stalled"])
        self.assertEqual(result["stop_reason"], "terminal_event_process_stalled")
        self.assertFalse(result["capture_complete"])
        self.assertEqual(result["measurements"]["latency"]["end_to_end"]["coverage"], "partial-episode")

    def test_descendant_regular_file_handle_never_waits_for_pipe_eof(self) -> None:
        result = self.host("codex", """import subprocess,sys,json
subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],stdout=sys.stdout,stderr=sys.stderr)
print(json.dumps({"type":"item.completed","item":{"id":"a","type":"agent_message","text":"done"}}),flush=True)
print(json.dumps({"type":"turn.completed"}),flush=True)
""", timeout_seconds=1)
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["native_returncode_before_cleanup"], 0)
        self.assertIsNotNone(result["native_status"])
        if os.name == "nt":
            self.assertEqual(result["cleanup"], "complete")
        else:
            self.assertIn(result["cleanup"], ("complete", "incomplete"))
        for member in ("prompt.private.bin", "stdout.private.jsonl", "stderr.private.bin"):
            (self.out / "run" / member).unlink()

    @unittest.skipUnless(os.name == "nt", "Native Windows process-handle semantics.")
    def test_windows_cleanup_waits_for_disappearing_descendant_handles(self) -> None:
        cases = ((0.1, False, "complete"), (1.0, False, "incomplete"),
                 (0.1, True, "complete"), (1.0, True, "incomplete"))
        for exit_delay, already_exiting, expected in cases:
            with self.subTest(exit_delay=exit_delay, already_exiting=already_exiting):
                class Kernel:
                    now = 0.0
                    terminating = False
                    waits = 0
                    closed = []

                    def QueryInformationJobObject(self, job, kind, data, size, returned):
                        if kind == 1:
                            data._obj.active = 0
                        elif kind == 3:
                            data._obj.assigned = data._obj.listed = 0 if self.terminating else 1
                            if not self.terminating:
                                data._obj.pids[0] = 2
                        else:
                            raise AssertionError("Unexpected job query")
                        return 1

                    def OpenProcess(self, access, inherit, pid):
                        return pid

                    def IsProcessInJob(self, handle, job, member):
                        member._obj.value = True
                        return 1

                    def TerminateProcess(self, handle, code):
                        self.terminating = True
                        if already_exiting:
                            RUNNER.ctypes.set_last_error(5)
                            return 0
                        return 1

                    def TerminateJobObject(self, job, code):
                        self.terminating = True
                        return 1

                    def WaitForSingleObject(self, handle, milliseconds):
                        if handle == 1:
                            return 0
                        self.waits += 1
                        self.now += min(milliseconds / 1000, max(0, exit_delay - self.now))
                        return 0 if self.terminating and self.now >= exit_delay else 258

                    def CloseHandle(self, handle):
                        self.closed.append(handle)
                        return 1

                    def sleep(self, seconds):
                        self.now += seconds

                kernel = Kernel()
                tree = RUNNER.ProcessTree.__new__(RUNNER.ProcessTree)
                tree.job, tree.kernel = 99, kernel
                tree.process = SimpleNamespace(pid=1, _handle=1, poll=lambda: 0)
                tree.cleanup = "running"
                with patch.object(RUNNER.time, "monotonic", side_effect=lambda: kernel.now), \
                     patch.object(RUNNER.time, "sleep", side_effect=kernel.sleep):
                    result = tree.stop(0.2)
                self.assertEqual(result, expected)
                self.assertGreater(kernel.waits, 0)
                self.assertEqual(kernel.closed, [2])
                self.assertLessEqual(kernel.now, 0.201)
                if expected == "complete":
                    self.assertGreaterEqual(kernel.now, exit_delay)

    @unittest.skipUnless(os.name == "nt", "Native Windows membership proof.")
    def test_windows_cleanup_never_queries_a_closed_job(self) -> None:
        tree = RUNNER.ProcessTree.__new__(RUNNER.ProcessTree)
        tree.job, tree.kernel = None, Mock()
        tree.process = SimpleNamespace(pid=1, _handle=1, poll=lambda: 0)
        tree.cleanup = "running"
        self.assertEqual(tree.stop(0.2), "incomplete")
        self.assertEqual(tree.kernel.mock_calls, [])

    def posix_tree(self, killpg) -> tuple[object, object]:
        tree = RUNNER.ProcessTree.__new__(RUNNER.ProcessTree)
        tree.process = SimpleNamespace(pid=4321, poll=lambda: 0)
        tree.cleanup = "running"
        return tree, patch.object(RUNNER, "os", SimpleNamespace(name="posix", killpg=killpg))

    @unittest.skipIf(os.name == "nt", "POSIX process-group signals.")
    def test_posix_cleanup_waits_through_zombie_eperm_until_esrch(self) -> None:
        probes = []

        def killpg(pid, sig):
            if sig == 0:
                probes.append(pid)
                if len(probes) <= 3:
                    raise PermissionError(1, "Operation not permitted")
                raise ProcessLookupError(3, "No such process")

        tree, posix = self.posix_tree(killpg)
        with posix:
            self.assertEqual(tree.stop(1.0), "complete")
        self.assertEqual(len(probes), 4)

    @unittest.skipIf(os.name == "nt", "POSIX process-group signals.")
    def test_posix_cleanup_never_treats_eperm_as_exit(self) -> None:
        def killpg(pid, sig):
            raise PermissionError(1, "Operation not permitted")

        tree, posix = self.posix_tree(killpg)
        with posix:
            self.assertEqual(tree.stop(0.2), "incomplete")

    @unittest.skipUnless(os.name == "nt", "Native Windows membership proof.")
    def test_windows_cleanup_refuses_unverified_members(self) -> None:
        for failure in ("snapshot", "open", "membership", "wait"):
            with self.subTest(failure=failure):
                def membership(handle, job, member):
                    member._obj.value = failure != "membership"
                    return 1

                RUNNER.ctypes.set_last_error(5)
                kernel = SimpleNamespace(
                    OpenProcess=Mock(return_value=0 if failure == "open" else 2),
                    IsProcessInJob=membership,
                    WaitForSingleObject=Mock(side_effect=lambda handle, ms: 0 if handle == 1 else 0xFFFFFFFF),
                    TerminateProcess=Mock(return_value=1),
                    TerminateJobObject=Mock(return_value=1),
                    CloseHandle=Mock(return_value=1),
                )
                tree = RUNNER.ProcessTree.__new__(RUNNER.ProcessTree)
                tree.job, tree.kernel = 99, kernel
                tree.process = SimpleNamespace(pid=1, _handle=1, poll=lambda: 0)
                tree.cleanup = "running"
                tree._windows_pids = Mock(return_value=None if failure == "snapshot" else [2])
                self.assertEqual(tree.stop(0.2), "incomplete")
                kernel.TerminateProcess.assert_not_called()
                kernel.TerminateJobObject.assert_called_once_with(99, 1)
                if failure in ("membership", "wait"):
                    kernel.CloseHandle.assert_called_once_with(2)
                else:
                    kernel.CloseHandle.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Native Windows job query layout.")
    def test_windows_membership_query_requires_a_complete_bounded_snapshot(self) -> None:
        capacities = []

        def query(job, kind, data, size, returned):
            self.assertEqual(kind, 3)
            capacity = len(data._obj.pids)
            capacities.append(capacity)
            data._obj.assigned = 65
            data._obj.listed = min(capacity, 65)
            for index in range(data._obj.listed):
                data._obj.pids[index] = index + 1
            if capacity < 65:
                RUNNER.ctypes.set_last_error(234)
                return 0
            return 1

        tree = RUNNER.ProcessTree.__new__(RUNNER.ProcessTree)
        tree.job = 99
        tree.kernel = SimpleNamespace(QueryInformationJobObject=query)
        self.assertEqual(tree._windows_pids(time.monotonic() + 1), list(range(1, 66)))
        self.assertEqual(capacities, [64, 128])
        RUNNER.ctypes.set_last_error(6)
        tree.kernel.QueryInformationJobObject = Mock(return_value=0)
        self.assertIsNone(tree._windows_pids(time.monotonic() + 1))
        tree.kernel.QueryInformationJobObject.assert_called_once()
        tree.kernel.QueryInformationJobObject.reset_mock()
        self.assertIsNone(tree._windows_pids(time.monotonic()))
        tree.kernel.QueryInformationJobObject.assert_not_called()

    def test_no_trace_does_not_claim_zero_asg_calls(self) -> None:
        result = self.host("codex", """import json
print(json.dumps({"type":"item.completed","item":{"id":"a","type":"agent_message","text":"done"}}),flush=True)
print(json.dumps({"type":"turn.completed"}),flush=True)
""")
        self.assertEqual(result["measurements"]["calls"]["asg_operation_count"]["status"], "unavailable")
        self.assertNotIn("value", result["measurements"]["calls"]["asg_operation_count"])

    def test_native_error_and_stderr_stay_private(self) -> None:
        result = self.host("codex", """import json,sys
print(json.dumps({"type":"error","message":"private synthetic details"}),flush=True)
print(json.dumps({"type":"turn.failed","error":{"message":"synthetic failure"}}),flush=True)
print("private synthetic stderr",file=sys.stderr,flush=True)
sys.exit(17)
""")
        self.assertEqual(result["native_returncode_before_cleanup"], 17)
        self.assertEqual(result["native_status"], "turn.failed")
        self.assertEqual(result["native_error_count"], 2)
        self.assertNotIn("private synthetic", json.dumps(result))
        self.assertIn(b"private synthetic", (self.out / "run" / "stderr.private.bin").read_bytes())


    def test_proxy_jsonl_tools_list_and_duplicate_payload_exact_bytes(self) -> None:
        request = jsonl({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + jsonl({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "search_sessions", "arguments": {"query": "中文\u2028文字", "limit": 5, "max_bytes": 8192}}})
        payload = {"outcome": "success", "data": {"excerpt": "中文\u2028证据", "value": 2}}
        response_one = jsonl({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "search_sessions"}]}})
        response_two = jsonl({"jsonrpc": "2.0", "id": 2, "result": {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "structuredContent": payload, "isError": False}})
        child = """import sys,json
for line in sys.stdin.buffer:
 value=json.loads(line)
 if value.get("method")=="tools/list":
  result={"tools":[{"name":"search_sessions"}]}
 else:
  payload={"outcome":"success","data":{"excerpt":"中文\\u2028证据","value":2}}
  result={"content":[{"type":"text","text":json.dumps(payload,ensure_ascii=False)}],"structuredContent":payload,"isError":False}
 sys.stdout.buffer.write(json.dumps({"jsonrpc":"2.0","id":value["id"],"result":result},ensure_ascii=False,separators=(",",":")).encode()+b"\\n")
 sys.stdout.buffer.flush()
"""
        result, forwarded = self.proxy(child, request)
        expected = response_one + response_two
        self.assertEqual(forwarded, expected)
        self.assertEqual((self.out / "proxy" / "request.bin").read_bytes(), request)
        self.assertEqual((self.out / "proxy" / "response.bin").read_bytes(), expected)
        self.assertTrue(result["wire"]["complete"])
        self.assertEqual(result["wire"]["trace_completeness"], "complete")
        self.assertEqual(len(result["wire"]["trace"]), 1)
        self.assertEqual(result["transport"]["asg_total_bytes"]["value"], len(request) + len(expected))
        self.assertEqual(result["wire"]["capture_sha256"]["response"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(result["wire"]["trace"][0]["response_sha256"], hashlib.sha256(response_two).hexdigest())
        self.assertNotIn("中文", json.dumps(result, ensure_ascii=False))
        events = [json.loads(line) for line in (self.out / "proxy" / "wire-events.private.jsonl").read_bytes().split(b"\n") if line]
        self.assertTrue(any(row["kind"] == "frame" and row["message"].get("result", {}).get("structuredContent") for row in events))
        self.assertTrue(any(row["kind"] == "forwarded" for row in events))

    def test_proxy_content_length_nonascii_one_byte_chunks(self) -> None:
        value = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_message", "arguments": {"synthetic": "证据\u2028"}}}
        request = header_frame(value)
        child = """import os,sys,time
while True:
 data=os.read(sys.stdin.fileno(),1)
 if not data:break
 os.write(sys.stdout.fileno(),data)
"""
        result, forwarded = self.proxy(child, request)
        self.assertEqual(forwarded, request)
        self.assertEqual(result["wire"]["frame_count"], 2)
        self.assertTrue(result["wire"]["parsed_complete"])
        self.assertEqual(result["transport"]["asg_request_bytes"]["value"], len(request))
        self.assertEqual(result["wire"]["forwarded_bytes"], result["wire"]["received_bytes"])

    def test_frame_parser_preserves_crlf_and_embedded_unicode_line_separator(self) -> None:
        seen = []
        reader = RUNNER.FrameReader(lambda *row: seen.append(row))
        frame = jsonl({"id": 2, "text": "中文\u2028not-a-newline"}).replace(b"\n", b"\r\n")
        for byte in frame:
            reader.feed(bytes([byte]), 20)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][2], len(frame))
        self.assertEqual(seen[0][3], hashlib.sha256(frame).hexdigest())
        self.assertTrue(reader.complete())

    def test_partial_response_forwarding_preserves_exact_finite_pipe_bytes(self) -> None:
        # Pre-fill a finite real pipe: interpreter startup is not a prerequisite
        # for exercising the partial-frame forwarding and capture paths.
        prefix = b'{"synthetic":"partial'
        output = RUNNER.create_output(self.out, "finite-partial")
        capture = RUNNER.WireCapture(output)
        destination_path = self.work / "finite-partial-output.bin"
        read_fd, write_fd = os.pipe()
        done = threading.Event()
        try:
            with os.fdopen(read_fd, "rb", buffering=0) as source, os.fdopen(write_fd, "wb", buffering=0) as writer:
                self.assertEqual(writer.write(prefix), len(prefix))
                writer.close()
                with destination_path.open("wb", buffering=0) as destination:
                    RUNNER.pump_stream(source, destination, "response", capture, done, close_destination=False)
            state = capture.snapshot(False)
        finally:
            capture.close()
        self.assertTrue(done.is_set())
        self.assertEqual(destination_path.read_bytes(), prefix)
        self.assertEqual((output / "response.bin").read_bytes(), prefix)
        self.assertEqual(state["received_bytes"]["response"], len(prefix))
        self.assertEqual(state["forwarded_bytes"]["response"], len(prefix))
        self.assertEqual(state["capture_sha256"]["response"], hashlib.sha256(prefix).hexdigest())
        self.assertTrue(state["eof"]["response"])
        self.assertEqual(state["errors"], [])
        self.assertFalse(state["complete"])
        self.assertFalse(state["parsed_complete"])
        self.assertEqual(state["trace_completeness"], "partial")
        self.assertEqual(state["frame_count"], 0)

    def test_proxy_timeout_preserves_original_native_launch_budget_without_success(self) -> None:
        # A real 0.2-second launch can expire before Python emits any bytes.
        # Exact partial forwarding is proved separately by the finite-pipe test.
        result, forwarded = self.proxy("import time\ntime.sleep(30)\n", b"", timeout_seconds=0.2)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["execution_state"], "failed")
        self.assertFalse(result["wire"]["complete"])
        self.assertEqual(result["transport"]["asg_total_bytes"]["coverage"], "partial-episode")
        self.assertEqual(result["acceptance"], "open")
        self.assertEqual(forwarded, b"")
        self.assertEqual((self.out / "proxy" / "response.bin").read_bytes(), b"")
        if os.name == "nt":
            self.assertEqual(result["cleanup"], "complete")
            self.assertIsNotNone(result["native_returncode"])
        self.assertGreaterEqual(result["ended_monotonic_ns"] - result["started_monotonic_ns"], 200_000_000)

    def test_proxy_timeout_captures_partial_bytes_without_success(self) -> None:
        # A finite fixture removes native startup from the partial-wire proof.
        # Real forwarding threads must finish before a process observation crosses
        # the unchanged 0.2-second original deadline and reports a zero exit code.
        # This is a deadline unit fixture, not native process or latency evidence.
        prefix = b'{"synthetic":"partial'
        stdin_path = self.work / "completed-stdin.bin"
        stdout_path = self.work / "completed-stdout.bin"
        stdout_path.write_bytes(prefix)
        finished = {direction: threading.Event() for direction in ("request", "response")}
        original_pump = RUNNER.pump_stream

        def observed_pump(source, destination, direction, capture, done, **kwargs):
            original_pump(source, destination, direction, capture, done, **kwargs)
            finished[direction].set()

        class CompletedProcess:
            def __init__(self, stdin, stdout):
                self.stdin, self.stdout = stdin, stdout
                self.first_poll = True

            def poll(self):
                if self.first_poll:
                    self.first_poll = False
                    if not all(event.wait(2) for event in finished.values()):
                        raise AssertionError("Finite forwarding did not finish before process observation.")
                    time.sleep(0.25)
                return 0

        with stdin_path.open("wb", buffering=0) as stdin_handle, stdout_path.open("rb", buffering=0) as stdout_handle:
            completed = CompletedProcess(stdin_handle, stdout_handle)
            with patch.object(RUNNER.ProcessTree, "spawn", return_value=completed), \
                 patch.object(RUNNER.ProcessTree, "stop", return_value="complete"), \
                 patch.object(RUNNER, "pump_stream", side_effect=observed_pump):
                result, forwarded = self.proxy("raise SystemExit(0)\n", prefix, timeout_seconds=0.2)
        self.assertEqual(result["native_returncode"], 0)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["execution_state"], "failed")
        self.assertFalse(result["wire"]["complete"])
        self.assertFalse(result["wire"]["parsed_complete"])
        self.assertEqual(result["transport"]["asg_total_bytes"]["coverage"], "partial-episode")
        self.assertEqual(result["acceptance"], "open")
        self.assertEqual(forwarded, prefix)
        self.assertEqual((self.out / "proxy" / "request.bin").read_bytes(), prefix)
        self.assertEqual((self.out / "proxy" / "response.bin").read_bytes(), prefix)
        self.assertEqual(stdin_path.read_bytes(), prefix)
        self.assertEqual(result["wire"]["received_bytes"], {"request": len(prefix), "response": len(prefix)})
        self.assertEqual(result["wire"]["forwarded_bytes"], result["wire"]["received_bytes"])
        self.assertEqual(result["wire"]["capture_sha256"]["response"], hashlib.sha256(prefix).hexdigest())
        self.assertEqual(result["transport"]["asg_total_bytes"]["value"], len(prefix) * 2)
        self.assertGreaterEqual(result["ended_monotonic_ns"] - result["started_monotonic_ns"], 200_000_000)

    def test_proxy_missing_digest_refuses_spawn(self) -> None:
        command = self.child("raise SystemExit(99)")
        with self.assertRaises(RUNNER.CaptureError):
            RUNNER.proxy_stdio(command, expected_executable_sha256="0" * 64, workdir=self.work,
                               output_root=self.out, run_id="no-spawn", timeout_seconds=1)
        self.assertFalse((self.out / "no-spawn").exists())

    def test_proxy_child_crash_preserves_exit_and_missing_response(self) -> None:
        result, output = self.proxy("raise SystemExit(23)", jsonl({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "get_message"}}))
        self.assertEqual(result["native_returncode"], 23)
        self.assertEqual(output, b"")
        self.assertFalse(result["wire"]["trace"][0]["response_received"])
        self.assertIsNone(result["wire"]["trace"][0]["response_sha256"])

    def test_output_no_overwrite_no_traversal_and_no_root_create(self) -> None:
        output = RUNNER.create_output(self.out, "owned")
        member = output / "sentinel"
        member.write_bytes(b"preserve")
        with self.assertRaises(RUNNER.CaptureError):
            RUNNER.create_output(self.out, "owned")
        with self.assertRaises(RUNNER.CaptureError):
            RUNNER.create_output(self.out, "../escape")
        with self.assertRaises(OSError):
            RUNNER.create_output(self.root / "missing", "unused")
        self.assertEqual(member.read_bytes(), b"preserve")
        self.assertFalse((self.root / "missing").exists())

    def test_output_link_rejected(self) -> None:
        link = self.root / "linked"
        try:
            link.symlink_to(self.out, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation is unavailable on this native host.")
        with self.assertRaises(RUNNER.CaptureError):
            RUNNER.create_output(link, "unused")
        self.assertFalse((self.out / "unused").exists())

    def test_output_under_tracked_directory_is_rejected(self) -> None:
        with self.assertRaises(RUNNER.CaptureError):
            RUNNER.create_output(MODULE_PATH.parent, "never-create-private")
        self.assertFalse((MODULE_PATH.parent / "never-create-private").exists())

    def test_native_argv_preserves_permissions_and_supplied_config(self) -> None:
        settings = self.profile / "settings.json"
        mcp = self.profile / "mcp.json"
        settings.write_text("{}")
        mcp.write_text("{}")
        args = RUNNER.host_argv("claude-code", [str(self.executable)], self.work,
                                settings=settings, mcp_config=mcp, max_turns=4)
        self.assertIn("--strict-mcp-config", args)
        self.assertIn("--max-turns", args)
        self.assertNotIn("--dangerously-skip-permissions", args)
        args = RUNNER.host_argv("codex", [str(self.executable)], self.work, config_profile="fixture")
        self.assertIn("--profile", args)
        self.assertNotIn("--full-auto", args)
        self.assertNotIn("--yolo", args)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", args)

    def test_cli_invalid_private_path_is_not_echoed(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = RUNNER.main(["run", "--executable", str(self.work / "private-missing")])
        self.assertEqual(code, 2)
        self.assertNotIn(str(self.work), stdout.getvalue() + stderr.getvalue())
        self.assertNotIn("private-missing", stderr.getvalue())

    def test_python310_ast_and_help_without_host_execution(self) -> None:
        import ast
        ast.parse(MODULE_PATH.read_text(encoding="utf-8"), feature_version=(3, 10))
        for mode in ("run", "proxy"):
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as exit_:
                RUNNER.parser().parse_args([mode, "--help"])
            self.assertEqual(exit_.exception.code, 0)
            self.assertIn("--timeout-seconds", output.getvalue())


    def test_native_assistant_usage_without_result_is_partial_not_full(self) -> None:
        native = RUNNER.NativeEvents("claude-code", "asg")
        native.feed({"type": "assistant", "message": {"usage": {"input_tokens": 5, "output_tokens": 2}}}, 10)
        native.feed({"type": "result", "subtype": "success", "result": "done"}, 11)
        metrics = native.tokens(True)
        self.assertEqual(metrics["model_input_tokens"]["coverage"], "partial-episode")
        self.assertEqual(metrics["model_input_tokens"]["value"], 5)
        self.assertEqual(metrics["model_total_tokens"]["status"], "unavailable")

    def test_proxy_error_response_copied_without_rewrite(self) -> None:
        request = jsonl({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_message"}})
        response = jsonl({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "synthetic error 中文"}})
        child = "import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(" + repr(response) + ")\nsys.stdout.buffer.flush()\n"
        result, received = self.proxy(child, request)
        self.assertEqual(received, response)
        self.assertTrue(result["wire"]["complete"])
        self.assertEqual(result["transport"]["asg_response_bytes"]["value"], len(response))
        self.assertNotIn("synthetic error", json.dumps(result))

    def test_proxy_forwarding_error_is_partial(self) -> None:
        request = jsonl({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        response = jsonl({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        command = self.child("import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(" + repr(response) + ")\nsys.stdout.buffer.flush()\n")
        input_path = self.work / "partial-input.bin"
        output_path = self.work / "read-only.bin"
        input_path.write_bytes(request)
        output_path.write_bytes(b"")
        with input_path.open("rb", buffering=0) as input_handle, output_path.open("rb", buffering=0) as output_handle:
            result = RUNNER.proxy_stdio(command, expected_executable_sha256=self.executable_sha,
                                        workdir=self.work, output_root=self.out, run_id="io-failure",
                                        timeout_seconds=1, input_stream=input_handle, output_stream=output_handle)
        self.assertFalse(result["wire"]["complete"])
        self.assertIn("forwarding_io_failed", result["wire"]["errors"])
        self.assertEqual(result["wire"]["received_bytes"]["response"], len(response))
        self.assertEqual(result["wire"]["forwarded_bytes"]["response"], 0)

    def test_parent_input_kept_open_never_claims_complete_proxy(self) -> None:
        read_fd, write_fd = os.pipe()
        source = os.fdopen(read_fd, "rb", buffering=0)
        output_path = self.work / "open-input-output.bin"
        try:
            with output_path.open("wb", buffering=0) as destination:
                started = time.monotonic()
                result = RUNNER.proxy_stdio(self.child("raise SystemExit(0)"), expected_executable_sha256=self.executable_sha,
                                            workdir=self.work, output_root=self.out, run_id="open-input",
                                            timeout_seconds=1, input_stream=source, output_stream=destination)
                self.assertLess(time.monotonic() - started, 2)
            self.assertFalse(result["wire"]["complete"])
            self.assertFalse(result["wire"]["eof"]["request"])
            self.assertEqual(result["transport"]["asg_total_bytes"]["coverage"], "partial-episode")
        finally:
            os.close(write_fd)
            time.sleep(0.05)
            source.close()

    @unittest.skipUnless(os.name == "nt", "Native Windows Job admission proof.")
    def test_windows_descendants_are_stopped_without_pid_guessing(self) -> None:
        heartbeat = self.work / "heartbeat.bin"
        child = """import subprocess,sys,json,time
heartbeat=sys.argv[1] if len(sys.argv)>1 and not sys.argv[1].startswith("-") else "heartbeat.bin"
script="import time; from pathlib import Path; p=Path('heartbeat.bin'); f=p.open('ab',buffering=0); f.write(b'x'); [ (f.write(b'x'), time.sleep(0.02)) for _ in range(1500) ]"
subprocess.Popen([sys.executable,"-u","-c",script],stdout=sys.stdout,stderr=sys.stderr)
time.sleep(0.15)
print(json.dumps({"type":"thread.started","thread_id":"synthetic"}),flush=True)
time.sleep(30)
"""
        result = self.host("codex", child, timeout_seconds=0.4)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["cleanup_method"], "windows-job-suspended-admission")
        self.assertEqual(result["cleanup"], "complete")
        self.assertTrue(heartbeat.exists())
        first = heartbeat.stat().st_size
        time.sleep(0.15)
        self.assertEqual(heartbeat.stat().st_size, first)
        with heartbeat.open("ab", buffering=0) as handle:
            handle.write(b"owned-after-cleanup")

    def test_bounded_native_tail_poll(self) -> None:
        path = self.work / "native-log.jsonl"
        path.write_bytes(jsonl({"type": "turn.started"}) * 20000)
        native = RUNNER.NativeEvents("codex", "asg")
        tail = RUNNER.EventTail(path, native)
        tail.poll()
        self.assertLessEqual(tail.offset, RUNNER.CHUNK * 4)
        self.assertLess(tail.offset, path.stat().st_size)

    def test_safe_scope_and_unknown_json_shape_do_not_rewrite_wire(self) -> None:
        scope, valid = RUNNER.safe_request_scope({"repo": "example.test/heldout/aurora", "providers": ["codex"],
            "since": "2026-02-02T00:00:00Z", "query": "private synthetic query"})
        self.assertTrue(valid)
        self.assertEqual(scope["repo"], "example.test/heldout/aurora")
        self.assertNotIn("query", scope)
        scope, valid = RUNNER.safe_request_scope({"providers": [{}], "tool_kind": {}})
        self.assertFalse(valid)
        self.assertEqual(scope, {})
        result, wire = self.proxy("import sys,os\nwhile True:\n d=os.read(sys.stdin.fileno(),65536)\n if not d:break\n os.write(sys.stdout.fileno(),d)\n", jsonl({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": {}, "arguments": {"providers": [{}]}}}))
        self.assertTrue(wire)
        self.assertEqual(result["wire"]["trace"][0]["operation_name"], "unknown_asg_tool")

    def test_failure_before_windows_admission_does_not_resume(self) -> None:
        if os.name != "nt":
            self.skipTest("Native Windows admission failure branch.")
        tree = RUNNER.ProcessTree()
        marker = self.work / "should-not-exist"
        command = self.child("from pathlib import Path\nPath('should-not-exist').write_text('bad')\n")
        class DeniedKernel:
            def __init__(self, real):
                self.real = real
            def __getattr__(self, name):
                return getattr(self.real, name)
            def AssignProcessToJobObject(self, *_):
                return 0
        tree.kernel = DeniedKernel(tree.kernel)
        with self.assertRaises(RUNNER.CaptureError):
            tree.spawn(command, cwd=self.work, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertFalse(marker.exists())


    def test_observation_matches_frozen_field_shape_and_stays_open(self) -> None:
        summary = self.host("codex", "import json\nprint(json.dumps({'type':'item.completed','item':{'id':'a','type':'agent_message','text':'done'}}),flush=True)\nprint(json.dumps({'type':'turn.completed','usage':{'input_tokens':46,'cached_input_tokens':11,'output_tokens':9}}),flush=True)\n")
        fields = ["run_id", "case_id", "repeat_ordinal", "description_variant", "execution_state", "host",
                  "host_version", "model_identity", "model_settings_sha256", "description_sha256", "candidate_archive_sha256",
                  "candidate_manifest_sha256", "candidate_source_identity", "pack_sha256", "corpus_sha256", "case_set_sha256",
                  "rendered_host_input_sha256", "policy_epoch", "catalog_incarnation", "snapshot_generation", "source_resolution",
                  "current_session_identity", "lifecycle", "asg_trace_completeness", "asg_trace", "measurements",
                  "token_counter_semantics", "final_response_sha256", "continuation_json_observed", "verdicts", "findings", "blocker_codes"]
        properties = {key: {} for key in fields}
        properties["verdicts"] = {"properties": {key: {} for key in
            ("trigger", "scope", "evidence_origin", "answer_claims", "continuation", "budget", "measurements", "overall")}}
        pack = {"cases": [{"case_id": "cx-n01", "host": "codex", "expected": {"asg_call": "forbidden"}}],
                "determinism": {"corpus_sha256": "1" * 64, "case_set_sha256": "2" * 64},
                "capture": {"observation_schema": {"properties": properties}}}
        metadata = {"run_id": "synthetic-run", "case_id": "cx-n01", "repeat_ordinal": 1,
                    "description_variant": "baseline", "pack_sha256": "3" * 64,
                    "corpus_sha256": "1" * 64, "case_set_sha256": "2" * 64}
        observation = RUNNER.make_observation(summary, metadata, pack)
        self.assertEqual(set(observation), set(fields))
        self.assertEqual(observation["verdicts"]["overall"], "open")
        self.assertEqual(observation["asg_trace_completeness"], "partial")
        self.assertEqual(observation["measurements"]["calls"]["asg_operation_count"]["status"], "unavailable")
        token_metrics = observation["measurements"]["tokens"]
        self.assertEqual(token_metrics["model_input_tokens"]["value"], 46)
        self.assertEqual(token_metrics["model_input_tokens"]["coverage"], "partial-episode")
        self.assertIn("stdout-thread-cumulative", token_metrics["model_input_tokens"]["method"])
        self.assertEqual(token_metrics["model_total_tokens"]["status"], "unavailable")
        self.assertEqual(token_metrics, summary["measurements"]["tokens"])
        self.assertIsNone(observation["continuation_json_observed"])
        bad_metadata = dict(metadata, candidate_source_identity=str(self.work))
        with self.assertRaises(RUNNER.CaptureError):
            RUNNER.make_observation(summary, bad_metadata, pack)
        result, _ = self.proxy("import sys\nsys.stdin.buffer.read()\n", b"", run_id="linked-proxy")
        with self.assertRaises(RUNNER.CaptureError):
            RUNNER.make_observation(summary, metadata, pack, wire=result)
        linked = dict(metadata, proxy_linked_run_id=summary["run_id"], proxy_executable_sha256=self.executable_sha,
                      proxy_covers_all_asg_channels=True)
        merged = RUNNER.make_observation(summary, linked, pack, wire=result)
        self.assertEqual(merged["measurements"]["calls"]["asg_operation_count"]["value"], 0)
        self.assertEqual(merged["lifecycle"]["called"], "not_applicable")
        self.assertEqual(merged["verdicts"]["overall"], "open")
        self.assertEqual(merged["measurements"]["tokens"], token_metrics)
        self.assertEqual(merged["measurements"]["tokens"]["model_input_tokens"]["coverage"], "partial-episode")
        linked["proxy_covers_all_asg_channels"] = False
        partial = RUNNER.make_observation(summary, linked, pack, wire=result)
        self.assertEqual(partial["asg_trace_completeness"], "partial")
        self.assertEqual(partial["measurements"]["transport"]["asg_total_bytes"]["coverage"], "partial-episode")

    def test_run_cli_with_fake_child_prints_no_paths_text_or_token_counters(self) -> None:
        script = self.work / "fake-cli.py"
        script.write_text("import json\nprint(json.dumps({'type':'item.completed','item':{'id':'a','type':'agent_message','text':'private synthetic answer'}}),flush=True)\nprint(json.dumps({'type':'turn.completed','usage':{'input_tokens':123,'cached_input_tokens':0,'output_tokens':5}}),flush=True)\n")
        prompt_file = self.work / "prompt.bin"
        prompt_file.write_bytes(b"private synthetic prompt")
        stdout, stderr = io.StringIO(), io.StringIO()
        original = RUNNER.host_argv
        def fake_host_argv(host, command, workdir, **kwargs):
            return [*command, "-u", str(script), *original(host, command, workdir, **kwargs)[1:]]
        with patch.object(RUNNER, "host_argv", side_effect=fake_host_argv), redirect_stdout(stdout), redirect_stderr(stderr):
            code = RUNNER.main(["run", "--host", "codex", "--executable", str(self.executable),
                                "--profile-dir", str(self.profile), "--working-dir", str(self.work),
                                "--prompt-file", str(prompt_file), "--output-root", str(self.out),
                                "--run-id", "cli-fixture", "--timeout-seconds", "2"])
        self.assertEqual(code, 0)
        rendered = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("private synthetic", rendered)
        self.assertNotIn("input_tokens", rendered)
        self.assertNotIn("123", rendered)
        self.assertEqual(json.loads(stdout.getvalue())["acceptance"], "open")

    def test_run_cli_default_grace_allows_delayed_clean_codex_exit(self) -> None:
        script = self.work / "fake-delayed-cli.py"
        script.write_text("""import json,sys,time
for event in [
    {"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"done"}},
    {"type":"turn.completed"},
]:
    sys.stdout.buffer.write(json.dumps(event).encode("utf-8") + b"\\n")
    sys.stdout.buffer.flush()
time.sleep(1.5)
""", encoding="utf-8")
        prompt_file = self.work / "prompt.bin"
        prompt_file.write_bytes(b"synthetic prompt")
        stdout, stderr = io.StringIO(), io.StringIO()
        original = RUNNER.host_argv
        def fake_host_argv(host, command, workdir, **kwargs):
            return [*command, "-u", str(script), *original(host, command, workdir, **kwargs)[1:]]
        with patch.object(RUNNER, "host_argv", side_effect=fake_host_argv), redirect_stdout(stdout), redirect_stderr(stderr):
            code = RUNNER.main(["run", "--host", "codex", "--executable", str(self.executable),
                                "--profile-dir", str(self.profile), "--working-dir", str(self.work),
                                "--prompt-file", str(prompt_file), "--output-root", str(self.out),
                                "--run-id", "delayed-cli-fixture", "--timeout-seconds", "8"])
        summary = json.loads((self.out / "delayed-cli-fixture" / "capture-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stop_reason"], "native_exit")
        self.assertFalse(summary["completed_but_stalled"])
        self.assertTrue(summary["capture_complete"])
        self.assertEqual(summary["native_returncode_before_cleanup"], 0)
        self.assertEqual(summary["execution_state"], "completed")
        self.assertEqual(code, 0)


    def test_echoed_request_is_not_invented_rpc_response(self) -> None:
        request = header_frame({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "get_message"}})
        result, returned = self.proxy("import os,sys\nwhile True:\n d=os.read(sys.stdin.fileno(),1)\n if not d:break\n os.write(sys.stdout.fileno(),d)\n", request)
        self.assertEqual(returned, request)
        self.assertTrue(result["wire"]["complete"])
        self.assertEqual(result["wire"]["trace_completeness"], "partial")
        self.assertFalse(result["wire"]["trace"][0]["response_received"])
        self.assertIsNone(result["wire"]["trace"][0]["response_sha256"])


if __name__ == "__main__":
    unittest.main()
