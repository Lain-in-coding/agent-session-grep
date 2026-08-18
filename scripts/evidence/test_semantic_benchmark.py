"""Unit tests for the frozen semantic benchmark (corpus, manifest, runner).

Determinism is the core contract: the same generator and seed must produce
byte-identical corpus files and manifest, and the committed fixtures must
still equal the generator output. The honesty contract is tested next: the
bigram-hash vectorizer may never be labeled as a real semantic model, and no
report may claim promotion while thresholds are pending.

The tests never touch real transcripts and never invoke the compiled binary:
everything except the CLI-runner path is exercised in-process.
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("semantic_benchmark.py")
SPEC = importlib.util.spec_from_file_location("semantic_benchmark", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SEM = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SEM
SPEC.loader.exec_module(SEM)

PRIVACY_SPEC = importlib.util.spec_from_file_location("privacy_scan", Path(__file__).with_name("privacy_scan.py"))
assert PRIVACY_SPEC is not None and PRIVACY_SPEC.loader is not None
PRIVACY = importlib.util.module_from_spec(PRIVACY_SPEC)
sys.modules[PRIVACY_SPEC.name] = PRIVACY
PRIVACY_SPEC.loader.exec_module(PRIVACY)


def generate_into_temp() -> tuple[Path, dict]:
    temp = tempfile.TemporaryDirectory(prefix="semantic-benchmark-test-")
    output_dir = Path(temp.name)
    manifest = SEM.generate_corpus(output_dir)
    return output_dir, manifest


class GeneratorDeterminismTests(unittest.TestCase):
    def test_same_seed_produces_byte_identical_output(self) -> None:
        """The frozen-contract core: same generator + seed = same bytes."""
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            SEM.generate_corpus(Path(first))
            SEM.generate_corpus(Path(second))
            first_files = sorted((Path(first) / "corpus").rglob("*.jsonl"))
            second_files = sorted((Path(second) / "corpus").rglob("*.jsonl"))
            self.assertTrue(first_files)
            self.assertEqual(len(first_files), len(second_files))
            for left, right in zip(first_files, second_files):
                self.assertEqual(
                    left.read_bytes(),
                    right.read_bytes(),
                    f"corpus file drifted: {left.name}",
                )
            self.assertEqual(
                (Path(first) / "manifest.json").read_bytes(),
                (Path(second) / "manifest.json").read_bytes(),
                "manifest drifted between two same-seed runs",
            )

    def test_committed_fixtures_equal_generator_output(self) -> None:
        """The committed corpus/manifest must still equal a fresh generation.

        This pins the committed artifacts: any hand-edit to the frozen
        fixtures breaks this test until the generator is updated deliberately.
        """
        with tempfile.TemporaryDirectory() as name:
            SEM.generate_corpus(Path(name))
            regenerated = sorted((Path(name) / "corpus" / "claude").glob("*.jsonl"))
            committed = SEM.corpus_files()
            self.assertEqual(len(regenerated), len(committed))
            for left, right in zip(regenerated, committed):
                # Compare with CRLF normalized: git's checkout conversion may
                # rewrite line endings on Windows; the frozen contract is the
                # logical content, not the on-disk EOL bytes.
                left_bytes = left.read_bytes().replace(b"\r\n", b"\n")
                right_bytes = right.read_bytes().replace(b"\r\n", b"\n")
                self.assertEqual(left_bytes, right_bytes, f"drift in {right.name}")
            self.assertEqual(
                (Path(name) / "manifest.json")
                .read_bytes()
                .replace(b"\r\n", b"\n"),
                SEM.MANIFEST_PATH.read_bytes().replace(b"\r\n", b"\n"),
                "committed manifest drifted from the generator",
            )

    def test_manifest_structure_is_frozen(self) -> None:
        manifest = SEM.load_manifest()
        self.assertEqual(manifest["corpus"]["session_count"], SEM.N_SESSIONS)
        self.assertEqual(manifest["corpus"]["message_count"], SEM.N_SESSIONS * SEM.MESSAGES_PER_SESSION)
        self.assertEqual(manifest["corpus"]["planted"]["near_duplicate_pairs"], SEM.N_DUPLICATE_PAIRS)
        self.assertEqual(manifest["corpus"]["planted"]["paraphrase_pairs"], SEM.N_PARAPHRASE_PAIRS)
        self.assertEqual(len(manifest["queries"]), 100)
        self.assertEqual(sum(manifest["corpus"]["language_mix"].values()), 2000)
        self.assertEqual(set(manifest["corpus"]["language_mix"]), {"zh", "en", "code"})

    def test_queries_carry_gold_labels_from_plant_bookkeeping(self) -> None:
        manifest = SEM.load_manifest()
        plants_by_id = {plant["plant_id"]: plant for plant in manifest["plants"]}
        texts = SEM.corpus_message_texts(SEM.CORPUS_DIR)
        self.assertEqual(len(texts), 2000)
        for query in manifest["queries"]:
            self.assertEqual(query["gold_derivation"], "generator_plant_bookkeeping")
            plant = plants_by_id[query["plant_id"]]
            self.assertEqual(query["gold_message_ids"], plant["message_ids"])
            for mid in query["gold_message_ids"]:
                self.assertIn(mid, texts)
            self.assertEqual(len(query["gold_session_ids"]), 2)
            for session_id in query["gold_session_ids"]:
                self.assertRegex(session_id, r"^semcorp-s\d{4}$")

    def test_plant_pairs_live_in_distinct_sessions(self) -> None:
        manifest = SEM.load_manifest()
        used: set[str] = set()
        for plant in manifest["plants"]:
            self.assertEqual(len(plant["message_ids"]), 2)
            self.assertNotEqual(plant["slots"][0][0], plant["slots"][1][0])
            for mid in plant["message_ids"]:
                self.assertNotIn(mid, used)
                used.add(mid)

    def test_every_query_is_and_semantics_reachable_from_gold(self) -> None:
        """The store matches FTS tokens with AND semantics (CJK bigrams on
        both sides), so EVERY distinctive token of a query must appear inside
        a single gold message — otherwise that query's gold label could never
        be lexically retrieved and the label would be dishonest."""
        manifest = SEM.load_manifest()
        texts = SEM.corpus_message_texts(SEM.CORPUS_DIR)
        for query in manifest["queries"]:
            query_tokens = SEM.distinctive_tokens(query["query"])
            reachable = any(
                query_tokens <= SEM.distinctive_tokens(texts[mid])
                for mid in query["gold_message_ids"]
            )
            self.assertTrue(
                reachable,
                f"query {query['id']!r} is not lexically reachable from any gold message",
            )

    def test_corpus_contains_no_privacy_rule_hits(self) -> None:
        """The synthetic corpus must never carry personal/machine paths."""
        for path in [SEM.MANIFEST_PATH, *SEM.corpus_files()]:
            relative = str(path.relative_to(Path(__file__).resolve().parents[2])).replace("\\", "/")
            findings = PRIVACY.scan_lines(
                relative, path.read_text(encoding="utf-8").splitlines(), frozenset()
            )
            self.assertEqual(findings, [], f"privacy hits in {relative}")


class RecallTests(unittest.TestCase):
    def test_recall_at_k_counts_ordered_truncation(self) -> None:
        hits = ["a", "b", "c", "d", "e", "f"]
        self.assertEqual(SEM.recall_at_k(hits, ["a", "b"], 2), 1.0)
        self.assertEqual(SEM.recall_at_k(hits, ["a", "b"], 1), 0.5)
        self.assertEqual(SEM.recall_at_k(hits, ["x", "b"], 5), 0.5)
        self.assertEqual(SEM.recall_at_k(hits, ["f", "g"], 5), 0.0)
        self.assertEqual(SEM.recall_at_k(hits, ["f", "g"], 20), 0.5)

    def test_recall_at_k_rejects_empty_gold_and_bad_k(self) -> None:
        with self.assertRaises(ValueError):
            SEM.recall_at_k(["a"], [], 5)
        with self.assertRaises(ValueError):
            SEM.recall_at_k(["a"], ["a"], 0)


class HonestLabelingTests(unittest.TestCase):
    BIGRAM_EMBEDDINGS = {
        "backend": "bigram-hash",
        "model_id": "bigram-hash-v1",
        "dimension": 384,
    }
    NO_MODEL = {"feature": None, "present": False, "verified": False}
    CANDLE_UNVERIFIED = {"feature": "semantic-candle", "present": True, "verified": False}
    CANDLE_VERIFIED = {"feature": "semantic-candle", "present": True, "verified": True}
    REAL_EMBEDDINGS = {
        "backend": "semantic-candle",
        "model_id": "intfloat/multilingual-e5-small",
        "dimension": 384,
    }

    def test_bigram_hash_is_never_labeled_as_a_real_model(self) -> None:
        labeling = SEM.label_model(self.BIGRAM_EMBEDDINGS, self.NO_MODEL)
        self.assertEqual(labeling["model"], "bigram-hash-v1")
        self.assertFalse(labeling["is_real_embedding_model"])
        self.assertTrue(labeling["threshold_pending"])
        self.assertEqual(labeling["promotion_claim"], "none")
        self.assertEqual(labeling["maturity"], "beta")

    def test_unverified_candle_bundle_stays_bigram_hash(self) -> None:
        labeling = SEM.label_model(self.BIGRAM_EMBEDDINGS, self.CANDLE_UNVERIFIED)
        self.assertFalse(labeling["is_real_embedding_model"])
        self.assertEqual(labeling["model"], "bigram-hash-v1")

    def test_real_bundle_records_measurements_but_claims_no_promotion(self) -> None:
        labeling = SEM.label_model(self.REAL_EMBEDDINGS, self.CANDLE_VERIFIED)
        self.assertTrue(labeling["is_real_embedding_model"])
        self.assertEqual(labeling["model"], "intfloat/multilingual-e5-small")
        # Real measurements are recorded, but thresholds stay pending and the
        # run must never claim promotion on its own.
        self.assertTrue(labeling["threshold_pending"])
        self.assertEqual(labeling["promotion_claim"], "none")
        self.assertEqual(labeling["maturity"], "beta")


def honest_report_dict(repeat: int = 1) -> dict:
    """Build a minimally honest report that validate_report must accept."""
    manifest = SEM.load_manifest()
    queries = manifest["queries"]
    per_query = {}
    for mode in SEM.MODES:
        per_query[mode] = [
            {
                "query_id": entry["id"],
                "query": entry["query"],
                "category": entry["category"],
                "requested_mode": mode,
                "effective_mode": mode,
                "fell_back": False,
                "gold_count": len(entry["gold_message_ids"]),
                "recalls": {f"recall_at_{k}": 1.0 for k in SEM.K_VALUES},
                "hit_ids": list(entry["gold_message_ids"]),
                "warnings": 0,
            }
            for entry in queries
        ]
    per_mode = {}
    for mode in SEM.MODES:
        per_mode[mode] = {
            f"recall_at_{k}": 1.0 for k in SEM.K_VALUES
        }
        per_mode[mode]["query_count"] = len(queries)
        per_mode[mode]["fell_back_query_count"] = 0
        per_mode[mode]["fell_back_repetitions"] = 0
    return {
        "schema_version": SEM.SCHEMA_VERSION,
        "generated_at_utc": "2026-08-16T00:00:00.000Z",
        "profile": "semantic",
        "commit": "f" * 40,
        "environment": {},
        "manifest": {
            "path": "scripts/evidence/fixtures/semantic/manifest.json",
            "schema_version": SEM.MANIFEST_SCHEMA_VERSION,
            "corpus_version": manifest["corpus_version"],
            "seed": manifest["seed"],
            "fixture_hash": manifest["corpus"]["fixture_hash"],
            "verified_against_committed_corpus": True,
        },
        "corpus": {
            "kind": "deterministic_synthetic_labeled",
            "contains_real_transcripts": False,
            "session_count": 200,
            "message_count": 2000,
            "planted": manifest["corpus"]["planted"],
            "query_count": len(queries),
        },
        "binary": {
            "hash_algorithm": "sha256",
            "binary_hash": "a" * 64,
            "provenance": "built_by_harness_from_workspace",
        },
        "catalog": {
            "sync": {"sources": 200, "emitted": 2000, "skipped": 0, "duration_ms": 1.0},
            "embeddings": {
                "backend": "bigram-hash",
                "model_id": "bigram-hash-v1",
                "dimension": 384,
                "indexed": 2000,
                "skipped": 0,
            },
            "embeddings_index_duration_ms": 1.0,
            "embeddings_warnings": [],
            "model_status": {"feature": None, "present": False, "verified": False},
        },
        "model_labeling": SEM.label_model(
            {"backend": "bigram-hash", "model_id": "bigram-hash-v1", "dimension": 384},
            {"feature": None, "present": False, "verified": False},
        ),
        "recall": {"k_values": list(SEM.K_VALUES), "per_mode": per_mode, "per_query": per_query},
        "latency_p50_p95_ms": {
            mode: {"p50": 1.0, "p95": 1.0, "count": len(queries) * repeat}
            for mode in SEM.MODES
        },
        "index_size": {
            "catalog_bytes_after_sync": 1000,
            "catalog_bytes_after_embeddings": 1200,
            "vector_projection_delta_bytes": 200,
        },
        "thresholds": {"state": "pending", "note": "x"},
        "repeat_counts": {"state": "pending", "used_in_this_run": repeat, "note": "x"},
        "gate": {"promotion_claim": "none", "lexical_stays_default": True, "maturity": "beta"},
        "limitations": [],
    }


class ReportValidationTests(unittest.TestCase):
    def test_validator_accepts_an_honest_report(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "report.json"
            path.write_text(json.dumps(honest_report_dict(), ensure_ascii=False), encoding="utf-8")
            SEM.validate_report(path)

    def test_validator_rejects_any_promotion_claim(self) -> None:
        for section, field, value in (
            ("model_labeling", "promotion_claim", "promoted"),
            ("model_labeling", "threshold_pending", False),
            ("gate", "promotion_claim", "promoted"),
            ("gate", "lexical_stays_default", False),
            ("gate", "maturity", "stable"),
            ("thresholds", "state", "frozen"),
        ):
            with self.subTest(mutation=(section, field, value)):
                report = honest_report_dict()
                report[section][field] = value
                with tempfile.TemporaryDirectory() as name:
                    path = Path(name) / "report.json"
                    path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        SEM.validate_report(path)

    def test_validator_rejects_bigram_hash_labeled_as_real_model(self) -> None:
        report = honest_report_dict()
        report["model_labeling"]["is_real_embedding_model"] = True
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "report.json"
            path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                SEM.validate_report(path)

    def test_validator_rejects_recall_out_of_range_and_wrong_counts(self) -> None:
        report = honest_report_dict()
        report["recall"]["per_mode"]["lexical"]["recall_at_5"] = 1.5
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "report.json"
            path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                SEM.validate_report(path)
        report = honest_report_dict()
        report["latency_p50_p95_ms"]["hybrid"]["count"] = 7
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "report.json"
            path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                SEM.validate_report(path)

    def test_validator_rejects_drifted_manifest_pin(self) -> None:
        report = honest_report_dict()
        report["manifest"]["fixture_hash"] = "0" * 64
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "report.json"
            path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                SEM.validate_report(path)


class ManifestValidationTests(unittest.TestCase):
    def test_manifest_validator_rejects_tampered_fixture(self) -> None:
        manifest = SEM.load_manifest()
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "manifest.json"
            bad = json.loads(json.dumps(manifest))
            bad["corpus"]["message_count"] = 1999
            path.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                SEM.validate_manifest_file(path)
            worse = json.loads(json.dumps(manifest))
            worse["benchmark_contract"]["thresholds"]["state"] = "frozen"
            path.write_text(json.dumps(worse, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                SEM.validate_manifest_file(path)

    def test_frozen_manifest_has_no_timestamps(self) -> None:
        """Byte-determinism requires the manifest to carry no clock values."""
        raw = SEM.MANIFEST_PATH.read_text(encoding="utf-8")
        self.assertNotIn("generated_at", raw)
        self.assertNotIn("T00:00:00.000Z", raw)


class RunnerArgValidationTests(unittest.TestCase):
    def test_parser_requires_a_subcommand(self) -> None:
        with self.assertRaises(SystemExit):
            SEM.parser().parse_args([])

    def test_run_rejects_non_positive_repeat(self) -> None:
        with self.assertRaises(SystemExit):
            SEM.parser().parse_args(["run", "--repeat", "0"])

    def test_resolve_binary_rejects_missing_path(self) -> None:
        args = SEM.parser().parse_args(
            ["run", "--binary", str(Path(tempfile.gettempdir()) / "no-such-binary.exe")]
        )
        with self.assertRaises(FileNotFoundError):
            SEM.resolve_binary(Path(__file__).resolve().parents[2], args)


if __name__ == "__main__":
    unittest.main()
