import contextlib
import copy
import importlib.util
import io
import json
import math
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("open_source_gate_benchmark.py")
SPEC = importlib.util.spec_from_file_location("open_source_gate_benchmark", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class GateManifestTests(unittest.TestCase):
    def test_labels_fixture_is_well_formed(self) -> None:
        labels = GATE.load_labels()
        self.assertEqual(labels["fixture_set_id"], "gate-synthetic-v1")
        self.assertTrue(labels["queries"])
        for entry in labels["queries"]:
            self.assertTrue(entry["query"])
            self.assertTrue(entry["expected_message_ids"])
            # Canonical session ids are digests over the corpus location, so the
            # labels pin provider-native ids and the harness resolves canonical
            # ids at run time. A pinned ses_v1_* here would break on any move.
            self.assertTrue(entry["expected_provider_session_ids"])
            self.assertNotIn("expected_session_ids", entry)
            for native in entry["expected_provider_session_ids"]:
                self.assertFalse(native.startswith("ses_v1_"))

    def test_discovery_roots_cover_every_fixture_group(self) -> None:
        # If a fixture group has no data-root mapping, discovery coverage would
        # plant it nowhere and silently measure a lower number.
        groups = {path.parent.name for path in GATE.corpus_files()}
        self.assertTrue(groups)
        self.assertTrue(groups.issubset(set(GATE.DISCOVERY_ROOTS)))

    def test_corpus_files_exclude_labels_manifest(self) -> None:
        files = GATE.corpus_files()
        self.assertTrue(files)
        for path in files:
            self.assertEqual(path.suffix, ".jsonl")
            self.assertNotEqual(path.name, "labels.json")

    def test_parse_loss_from_sync_frames(self) -> None:
        frames = [
            {"data": {"emitted": 4, "skipped": 0}},
            {"data": {"emitted": 4, "skipped": 1}},
        ]
        result = GATE.parse_loss_from_sync(frames)
        self.assertEqual(result["emitted"], 8)
        self.assertEqual(result["skipped"], 1)
        self.assertAlmostEqual(result["parse_loss_ratio"], 0.111111, places=5)

    def test_latency_p50_p95(self) -> None:
        samples = [{"duration_ms": float(value)} for value in [1, 2, 3, 4, 5]]
        result = GATE.latency_p50_p95(samples)
        self.assertEqual(result["p50"], 3.0)
        self.assertEqual(result["p95"], 5.0)
        self.assertEqual(result["count"], 5)

    def test_metric_entry_not_applicable_requires_reason(self) -> None:
        entry = GATE.metric_entry(
            "discovery_coverage",
            "ratio",
            None,
            0.95,
            None,
            state="not_applicable",
            reason="not yet implemented",
        )
        self.assertEqual(entry["state"], "not_applicable")
        self.assertIsNone(entry["value"])
        self.assertIsNone(entry["pass"])
        self.assertEqual(entry["reason"], "not yet implemented")

    def test_validator_accepts_na_and_rejects_bad_threshold(self) -> None:
        manifest = {
            "schema_version": GATE.GATE_SCHEMA_VERSION,
            "commit": "f" * 40,
            "corpus": {"contains_real_transcripts": False},
            "metrics": [
                GATE.metric_entry("lexical_recall_at_10", "ratio", 1.0, 0.95, True),
                GATE.metric_entry("parse_loss_ratio", "ratio", 0.0, 0.05, True),
                GATE.metric_entry(
                    "discovery_coverage",
                    "ratio",
                    None,
                    0.95,
                    None,
                    state="not_applicable",
                    reason="sync --discover not yet implemented",
                ),
                GATE.metric_entry(
                    "resume_handoff_success",
                    "count",
                    None,
                    1.0,
                    None,
                    state="not_applicable",
                    reason="resume execution not yet landed",
                ),
                GATE.metric_entry(
                    "semantic_recall_at_10",
                    "ratio",
                    1.0,
                    None,
                    None,
                    reason="bigram-hash vectorizer; no threshold until a real model lands",
                ),
                GATE.metric_entry(
                    "hybrid_recall_at_10",
                    "ratio",
                    1.0,
                    None,
                    None,
                    reason="RRF over bigram-hash vectors; no threshold yet",
                ),
            ],
            "gate": {
                "pass": True,
                "failures": [],
                "deferred": ["discovery_coverage", "resume_handoff_success"],
            },
        }
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            GATE.validate_manifest(path)
        bad = dict(manifest)
        bad["metrics"] = [
            GATE.metric_entry("lexical_recall_at_10", "ratio", 1.0, 0.5, True),
            *bad["metrics"][1:],
        ]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "bad.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(ValueError):
                GATE.validate_manifest(path)

    def test_informational_metric_must_not_carry_a_pass_verdict(self) -> None:
        # An informational metric with a pass flag would read as a gate result;
        # the validator rejects it so semantic recall can never gate a release
        # while the vectorizer is a bigram hash.
        manifest = {
            "schema_version": GATE.GATE_SCHEMA_VERSION,
            "commit": "f" * 40,
            "corpus": {"contains_real_transcripts": False},
            "metrics": [
                GATE.metric_entry("lexical_recall_at_10", "ratio", 1.0, 0.95, True),
                GATE.metric_entry("parse_loss_ratio", "ratio", 0.0, 0.05, True),
                GATE.metric_entry(
                    "discovery_coverage",
                    "ratio",
                    None,
                    0.95,
                    None,
                    state="not_applicable",
                    reason="not implemented",
                ),
                GATE.metric_entry(
                    "resume_handoff_success",
                    "count",
                    None,
                    1.0,
                    None,
                    state="not_applicable",
                    reason="not landed",
                ),
                # Illegal: threshold + pass on an informational metric.
                GATE.metric_entry("semantic_recall_at_10", "ratio", 1.0, 0.95, True),
                GATE.metric_entry(
                    "hybrid_recall_at_10", "ratio", 1.0, None, None, reason="ok"
                ),
            ],
            "gate": {
                "pass": True,
                "failures": [],
                "deferred": ["discovery_coverage", "resume_handoff_success"],
            },
        }
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "bad.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError):
                GATE.validate_manifest(path)

    def test_gate_verdict_decides_the_exit_status(self) -> None:
        # The manifest is only evidence; CI reads the exit code. A false verdict
        # must name the metrics that missed their threshold.
        self.assertIsNone(
            GATE.gate_failure_reason({"gate": {"pass": True, "failures": []}})
        )
        self.assertEqual(
            GATE.gate_failure_reason(
                {"gate": {"pass": False, "failures": ["lexical_recall_at_10"]}}
            ),
            "gate metrics below threshold: lexical_recall_at_10",
        )
        # A verdict that is absent or not a real boolean is not a pass either.
        self.assertIsNotNone(GATE.gate_failure_reason({}))
        self.assertIsNotNone(GATE.gate_failure_reason({"gate": {"pass": "true"}}))


class GateValidationRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "manifest.json"

    @staticmethod
    def manifest() -> dict:
        # Minimal synthetic evidence; no binary or transcript input is needed.
        return {
            "schema_version": GATE.GATE_SCHEMA_VERSION,
            "commit": "f" * 40,
            "corpus": {"contains_real_transcripts": False},
            "metrics": [
                GATE.metric_entry(
                    name, "ratio", 0.0 if name == "parse_loss_ratio" else 1.0,
                    threshold, True,
                )
                for name, threshold in GATE.GATE_THRESHOLDS.items()
            ] + [
                GATE.metric_entry(name, "ratio", 1.0, None, None, reason="informational only")
                for name in sorted(GATE.INFORMATIONAL_METRICS)
            ],
            "gate": {"pass": True, "failures": [], "deferred": []},
        }

    @classmethod
    def na_manifest(cls) -> dict:
        manifest = cls.manifest()
        for metric in manifest["metrics"]:
            if metric["name"] in ("discovery_coverage", "resume_handoff_success"):
                metric.update(state="not_applicable", value=None, reason="legacy deferred evidence")
                metric["pass"] = None
                if metric["name"] == "resume_handoff_success":
                    metric["unit"] = "count"
                manifest["gate"]["deferred"].append(metric["name"])
        return manifest

    def write_manifest(self, manifest: object) -> None:
        self.path.write_text(json.dumps(manifest), encoding="utf-8")

    def assert_valid(self, manifest: dict) -> None:
        self.write_manifest(manifest)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(GATE.validate_manifest(self.path), manifest)

    def assert_invalid(self, manifest: object, diagnostic: str) -> None:
        self.write_manifest(manifest)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, re.escape(diagnostic)):
                GATE.validate_manifest(self.path)

    def test_reproduced_false_accepts(self) -> None:
        cases = [
            ("zero recall", lambda m: m["metrics"][0].update(value=0.0), "lexical_recall_at_10.pass"),
            ("total loss", lambda m: m["metrics"][1].update(value=1.0), "parse_loss_ratio.pass"),
            ("false failure", lambda m: (
                m["metrics"][0].update({"pass": False}),
                m["gate"].update({"pass": False, "failures": ["lexical_recall_at_10"]}),
            ), "lexical_recall_at_10.pass"),
            ("duplicate", lambda m: m["metrics"].append(copy.deepcopy(m["metrics"][0])), "duplicates"),
            ("nan", lambda m: m["metrics"][0].update(value=float("nan")), ".value"),
            ("infinity", lambda m: m["metrics"][0].update(value=float("inf")), ".value"),
            ("negative", lambda m: m["metrics"][0].update(value=-1.0), ".value"),
            ("over one", lambda m: m["metrics"][0].update(value=2.0), ".value"),
            ("bool ratio", lambda m: m["metrics"][0].update(value=True), ".value"),
            ("numeric gate", lambda m: m["gate"].update({"pass": 1}), "gate.pass"),
            ("bool threshold", lambda m: m["metrics"][3].update(threshold=True), ".threshold"),
            ("informational state", lambda m: m["metrics"][4].update(state="broken"), ".state"),
            ("blank reason", lambda m: m["metrics"][4].update(reason="   "), ".reason"),
            ("non-hex commit", lambda m: m.update(commit="z" * 40), "commit"),
            ("wrong unit", lambda m: m["metrics"][0].update(unit="milliseconds"), ".unit"),
        ]
        for label, change, diagnostic in cases:
            with self.subTest(case=label):
                manifest = self.manifest()
                change(manifest)
                self.assert_invalid(manifest, diagnostic)

    def test_reproduced_container_errors(self) -> None:
        bad_metric = self.manifest()
        bad_metric["metrics"].append(None)
        bad_gate = self.manifest()
        bad_gate["gate"] = []
        for manifest, diagnostic in (([], "manifest"), (bad_metric, "metrics[6]"), (bad_gate, "gate")):
            with self.subTest(field=diagnostic):
                self.assert_invalid(manifest, diagnostic)

    def test_container_shapes_and_required_top_level_fields(self) -> None:
        for value in (None, False, 1, "object", []):
            with self.subTest(root=value):
                self.assert_invalid(value, "manifest")
            for field in ("corpus", "gate"):
                with self.subTest(field=field, value=value):
                    manifest = self.manifest()
                    manifest[field] = value
                    self.assert_invalid(manifest, field)
        for value in (None, False, 1, "metrics", {}, []):
            with self.subTest(metrics=value):
                manifest = self.manifest()
                manifest["metrics"] = value
                self.assert_invalid(manifest, "metrics")
        for value in (None, False, 1, "entry", []):
            with self.subTest(entry=value):
                manifest = self.manifest()
                manifest["metrics"][0] = value
                self.assert_invalid(manifest, "metrics[0]")
        for field in ("schema_version", "commit", "corpus", "metrics", "gate"):
            with self.subTest(missing=field):
                manifest = self.manifest()
                del manifest[field]
                self.assert_invalid(manifest, field)

    def test_metric_fields_are_explicit_even_when_null(self) -> None:
        for factory in (self.manifest, self.na_manifest):
            for index in range(6):
                for field in ("name", "unit", "state", "value", "threshold", "pass"):
                    with self.subTest(shape=factory.__name__, index=index, missing=field):
                        manifest = factory()
                        del manifest["metrics"][index][field]
                        self.assert_invalid(manifest, f"metrics[{index}].{field}")

    def test_exact_metric_names(self) -> None:
        for value in (None, True, 1, [], {}, "", "unknown_metric"):
            with self.subTest(name=value):
                manifest = self.manifest()
                manifest["metrics"][0]["name"] = value
                self.assert_invalid(manifest, "metrics[0].name")
        for index in range(6):
            with self.subTest(missing=index):
                manifest = self.manifest()
                manifest["metrics"].pop(index)
                self.assert_invalid(manifest, "metrics")
        manifest = self.manifest()
        manifest["metrics"][1] = copy.deepcopy(manifest["metrics"][0])
        self.assert_invalid(manifest, "duplicates")

    def test_threshold_boundaries_and_both_verdict_directions(self) -> None:
        # Freeze the contractual boundary and direction independently of the
        # implementation's comparison helper.
        boundaries = (
            ("lexical_recall_at_10", 0.95, False, True),
            ("parse_loss_ratio", 0.05, True, False),
            ("discovery_coverage", 0.95, False, True),
            ("resume_handoff_success", 1.0, False, None),
        )
        for name, boundary, below_pass, above_pass in boundaries:
            values = [(boundary, True), (math.nextafter(boundary, 0.0), below_pass)]
            if above_pass is not None:
                values.append((math.nextafter(boundary, 1.0), above_pass))
            for value, passes in values:
                with self.subTest(metric=name, value=value):
                    manifest = self.manifest()
                    metric = next(m for m in manifest["metrics"] if m["name"] == name)
                    metric.update(value=value)
                    metric["pass"] = passes
                    manifest["gate"].update({"pass": passes, "failures": [] if passes else [name]})
                    self.assert_valid(manifest)
                    # Even mutually consistent metric/gate flags cannot hide a
                    # contradiction with the measurement in either direction.
                    metric["pass"] = not passes
                    manifest["gate"].update({"pass": not passes, "failures": [name] if passes else []})
                    self.assert_invalid(manifest, f"{name}.pass")

    def test_all_measured_values_are_finite_ratios(self) -> None:
        values = (float("nan"), float("inf"), -float("inf"), -0.01, 1.01,
                  10**1000, -(10**1000), True, False, None, "0.95", [], {})
        for index in range(6):
            for value in values:
                with self.subTest(index=index, value=value):
                    manifest = self.manifest()
                    manifest["metrics"][index]["value"] = value
                    self.assert_invalid(manifest, ".value")

    def test_integer_endpoints_and_informational_zero_remain_valid(self) -> None:
        manifest = self.manifest()
        manifest["commit"] = "ABCDEF0123" * 4
        for metric in manifest["metrics"]:
            metric["value"] = 0 if metric["name"] in GATE.INFORMATIONAL_METRICS else int(metric["value"])
        manifest["metrics"][3]["threshold"] = 1
        self.assert_valid(manifest)

    def test_thresholds_require_fixed_non_bool_numbers(self) -> None:
        for index in range(4):
            for value in (None, True, False, "0.95", [], {}, float("nan"), float("inf"), 10**1000, 0.5):
                with self.subTest(index=index, threshold=value):
                    manifest = self.manifest()
                    manifest["metrics"][index]["threshold"] = value
                    self.assert_invalid(manifest, ".threshold")

    def test_metric_states_units_and_boolean_verdicts(self) -> None:
        for index in range(6):
            for state in (None, True, [], {}, "broken"):
                with self.subTest(index=index, state=state):
                    manifest = self.manifest()
                    manifest["metrics"][index]["state"] = state
                    self.assert_invalid(manifest, ".state")
            for unit in (None, [], "count", "milliseconds"):
                with self.subTest(index=index, unit=unit):
                    manifest = self.manifest()
                    manifest["metrics"][index]["unit"] = unit
                    self.assert_invalid(manifest, ".unit")
            for verdict in (0, 1, None, "true", [], {}):
                if index >= 4 and verdict is None:
                    continue
                with self.subTest(index=index, verdict=verdict):
                    manifest = self.manifest()
                    manifest["metrics"][index]["pass"] = verdict
                    self.assert_invalid(manifest, "pass")
        for index in (4, 5):
            manifest = self.manifest()
            manifest["metrics"][index]["state"] = "not_applicable"
            self.assert_invalid(manifest, ".state")
            manifest = self.manifest()
            manifest["metrics"][index]["threshold"] = 0.95
            self.assert_invalid(manifest, "threshold")

    def test_required_reasons_are_non_blank_strings(self) -> None:
        for index in (2, 3, 4, 5):
            for reason in (None, "", " \t\n", True, 1, [], {}):
                with self.subTest(index=index, reason=reason):
                    manifest = self.na_manifest()
                    manifest["metrics"][index]["reason"] = reason
                    self.assert_invalid(manifest, ".reason")
            manifest = self.na_manifest()
            del manifest["metrics"][index]["reason"]
            self.assert_invalid(manifest, ".reason")

    def test_na_null_fields_thresholds_and_legacy_unit(self) -> None:
        self.assert_valid(self.na_manifest())
        for index in range(4):
            manifest = self.manifest()
            metric = manifest["metrics"][index]
            metric.update(state="not_applicable", value=None, reason="synthetic NA")
            metric["pass"] = None
            manifest["gate"]["deferred"] = [metric["name"]]
            self.assert_valid(manifest)
            for field, value in (("value", 0), ("pass", False), ("threshold", None)):
                with self.subTest(index=index, field=field):
                    bad = copy.deepcopy(manifest)
                    bad["metrics"][index][field] = value
                    self.assert_invalid(bad, field)
            metric["unit"] = "count"
            if index == 3:
                self.assert_valid(manifest)
            else:
                self.assert_invalid(manifest, ".unit")

    def test_deferred_compatibility_and_exact_names(self) -> None:
        for factory in (self.manifest, self.na_manifest):
            for value in (None, [], False, 0, "", {}, [None], [[]], ["unknown"],
                          ["discovery_coverage", "discovery_coverage"]):
                with self.subTest(shape=factory.__name__, deferred=value):
                    manifest = factory()
                    manifest["gate"]["deferred"] = value
                    if factory == self.manifest and (value is None or value == []):
                        self.assert_valid(manifest)
                    else:
                        self.assert_invalid(manifest, "gate.deferred")
            manifest = factory()
            del manifest["gate"]["deferred"]
            if factory == self.manifest:
                self.assert_valid(manifest)
            else:
                self.assert_invalid(manifest, "gate.deferred")
        manifest = self.na_manifest()
        manifest["gate"]["deferred"].reverse()
        self.assert_valid(manifest)

    def test_aggregate_matches_recomputed_failures_in_metric_order(self) -> None:
        manifest = self.manifest()
        for index, value in ((0, 0.0), (1, 1.0)):
            manifest["metrics"][index].update({"value": value, "pass": False})
        names = ["lexical_recall_at_10", "parse_loss_ratio"]
        manifest["gate"].update({"pass": False, "failures": names})
        self.assert_valid(manifest)
        for failures in (None, False, 0, "", {}, [None], [[]], [], names[:1],
                         names[::-1], names + names[:1], ["unknown"]):
            with self.subTest(failures=failures):
                bad = copy.deepcopy(manifest)
                bad["gate"]["failures"] = failures
                self.assert_invalid(bad, "gate.failures")
        for base in (manifest, self.manifest()):
            for verdict in (None, 0, 1, "false", [], {}, not base["gate"]["pass"]):
                with self.subTest(original=base["gate"]["pass"], verdict=verdict):
                    bad = copy.deepcopy(base)
                    bad["gate"]["pass"] = verdict
                    self.assert_invalid(bad, "gate.pass")
            for field in ("pass", "failures"):
                bad = copy.deepcopy(base)
                del bad["gate"][field]
                self.assert_invalid(bad, f"gate.{field}")

    def test_commit_and_synthetic_declaration(self) -> None:
        for value in (None, True, 40, [], "f" * 39, "f" * 41, "g" * 40, "f" * 39 + "\n"):
            with self.subTest(commit=value):
                manifest = self.manifest()
                manifest["commit"] = value
                self.assert_invalid(manifest, "commit")
        for value in (None, True, 0, "false", [], {}):
            with self.subTest(contains_real_transcripts=value):
                manifest = self.manifest()
                manifest["corpus"]["contains_real_transcripts"] = value
                self.assert_invalid(manifest, "corpus.contains_real_transcripts")
        manifest = self.manifest()
        del manifest["corpus"]["contains_real_transcripts"]
        self.assert_invalid(manifest, "corpus.contains_real_transcripts")

    def test_validate_report_subprocess_diagnostics_and_numeric_overflow(self) -> None:
        valid = self.manifest()
        false_success = self.manifest()
        false_success["metrics"][0]["value"] = 0.0
        truthful_failure = copy.deepcopy(false_success)
        truthful_failure["metrics"][0]["pass"] = False
        truthful_failure["gate"].update({"pass": False, "failures": ["lexical_recall_at_10"]})
        cases = [("pass", valid, 0, ""), ("truthful failure", truthful_failure, 0, ""),
                 ("NA", self.na_manifest(), 0, ""),
                 ("false success", false_success, 1, "lexical_recall_at_10.pass"),
                 ("root", [], 1, "manifest")]
        for field in ("corpus", "gate", "metrics"):
            bad = self.manifest()
            bad[field] = None
            cases.append((field, bad, 1, field))
        bad = self.manifest()
        bad["metrics"][0] = None
        cases.append(("entry", bad, 1, "metrics[0]"))
        for label, manifest, status, diagnostic in cases:
            with self.subTest(case=label):
                self.write_manifest(manifest)
                result = subprocess.run(
                    [sys.executable, "-B", str(MODULE_PATH), "validate-report", str(self.path)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                if status:
                    self.assertTrue(result.stderr.startswith("error: "), result.stderr)
                    self.assertIn(diagnostic, result.stderr)
                    self.assertNotIn("valid ", result.stdout)
                else:
                    self.assertEqual(result.stderr, "")
                    self.assertIn("valid ", result.stdout)
        for number in ("1e400", "-1e400", "1" + "0" * 1000):
            with self.subTest(number=number):
                text = json.dumps(valid).replace('"value": 1.0', '"value": ' + number, 1)
                self.path.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-B", str(MODULE_PATH), "validate-report", str(self.path)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("error: lexical_recall_at_10.value", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_run_main_uses_gate_verdict_without_executing_a_binary(self) -> None:
        failed = self.manifest()
        failed["metrics"][0].update({"value": 0.0, "pass": False})
        failed["gate"].update({"pass": False, "failures": ["lexical_recall_at_10"]})
        for manifest, status in ((self.manifest(), 0), (self.na_manifest(), 0), (failed, 1)):
            with self.subTest(gate=manifest["gate"]):
                self.assert_valid(manifest)
                stderr = io.StringIO()
                with mock.patch.object(GATE, "run_gate", return_value=self.path) as run_gate:
                    with mock.patch.object(sys, "argv", [str(MODULE_PATH), "run"]):
                        with contextlib.redirect_stderr(stderr):
                            self.assertEqual(GATE.main(), status)
                    run_gate.assert_called_once()
                if status:
                    self.assertIn("gate metrics below threshold: lexical_recall_at_10", stderr.getvalue())
                else:
                    self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
