import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
