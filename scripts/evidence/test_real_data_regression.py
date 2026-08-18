"""Unit tests for the real-data regression harness.

The tests never touch real transcripts: they synthesise Claude Code fixtures,
so the whole suite is safe to run in CI. Tests that need the compiled binary
skip themselves when it is absent instead of failing, because the harness is
also edited on hosts that have not built the workspace.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import real_data_regression as rdr  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

# A recognisable token that must never leak into a report.
SECRET_TOKEN = "zqxjkbrw-corpus-secret-token"


def locate_binary():
    """Return the release binary, or None when the workspace is unbuilt."""
    override = os.environ.get("AGENT_SESSION_GREP_BINARY")
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None
    name = "agent-session-grep.exe" if os.name == "nt" else "agent-session-grep"
    candidate = REPO_ROOT / "target" / "release" / name
    return candidate if candidate.is_file() else None


def write_fixture(path: Path, session_uuid: str, tag: str) -> None:
    """Write a synthetic 3-record Claude Code transcript.

    Shape: root -> reply -> sidechain probe. The tag keeps each fixture's
    bytes distinct so the content-addressed document ids differ.
    """
    base = session_uuid[:-1]
    records = [
        {
            "type": "user",
            "uuid": f"{base}1",
            "parentUuid": None,
            "sessionId": session_uuid,
            "timestamp": "2026-07-27T01:00:00.000Z",
            "message": {"role": "user", "content": f"{SECRET_TOKEN} root {tag}"},
        },
        {
            "type": "assistant",
            "uuid": f"{base}2",
            "parentUuid": f"{base}1",
            "sessionId": session_uuid,
            "timestamp": "2026-07-27T01:00:01.000Z",
            "message": {"role": "assistant", "content": f"{SECRET_TOKEN} reply {tag}"},
        },
        {
            "type": "user",
            "uuid": f"{base}3",
            "parentUuid": f"{base}2",
            "isSidechain": True,
            "sessionId": session_uuid,
            "timestamp": "2026-07-27T01:00:02.000Z",
            "message": {"role": "user", "content": f"{SECRET_TOKEN} probe {tag}"},
        },
    ]
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def write_reparented_fixture(
    path: Path,
    session_uuid: str,
    shared_uuid: str,
    shared_text: str,
    tag: str,
) -> None:
    """Write a second session that reuses one stable Message under a new parent."""
    base = session_uuid[:-1]
    root_uuid = f"{base}1"
    records = [
        {
            "type": "user",
            "uuid": root_uuid,
            "parentUuid": None,
            "sessionId": session_uuid,
            "timestamp": "2026-07-27T01:10:00.000Z",
            "message": {"role": "user", "content": f"{SECRET_TOKEN} root {tag}"},
        },
        {
            "type": "assistant",
            "uuid": shared_uuid,
            "parentUuid": root_uuid,
            "sessionId": session_uuid,
            # Stable Message fields match the first fixture; only placement differs.
            "timestamp": "2026-07-27T01:00:01.000Z",
            "message": {"role": "assistant", "content": shared_text},
        },
        {
            "type": "user",
            "uuid": f"{base}3",
            "parentUuid": shared_uuid,
            "isSidechain": True,
            "sessionId": session_uuid,
            "timestamp": "2026-07-27T01:10:02.000Z",
            "message": {"role": "user", "content": f"{SECRET_TOKEN} probe {tag}"},
        },
    ]
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def sample_report(invariants=None):
    """A canonical, well-formed report built through the real constructor.

    ``invariants`` overrides the default all-passing verdict set, so tests can
    exercise how ``build_report`` derives ``outcome``.
    """
    if invariants is None:
        invariants = [
            rdr.invariant(id_, True, f"{id_} aggregate detail")
            for id_ in rdr.INVARIANT_IDS
        ]
    return rdr.build_report(
        generated_at_utc="2026-07-27T00:00:00Z",
        binary_basename="agent-session-grep.exe",
        version="0.1.0",
        sha256="0" * 64,
        environment={"os": "Windows", "release": "11", "python": "3.10.11"},
        source_files=2,
        total_bytes=1234,
        totals={"messages": 6, "sessions": 2, "documents": 2, "catalog_entities": 10},
        role_distribution={"user": 4, "assistant": 2},
        evidence_precision={"byte": 6, "line": 0, "record": 0, "unknown": 0},
        invariants=invariants,
    )


class PureFunctionTests(unittest.TestCase):
    """Report construction and invariant judgement need no binary."""

    def test_invariant_ids_are_complete_and_ordered(self):
        self.assertEqual(
            rdr.INVARIANT_IDS,
            (
                "INV-SYNC-OK",
                "INV-NO-PARSE-LOSS",
                "INV-SESSION-PRESENT",
                "INV-CONTEXT-NONEMPTY",
                "INV-SPAN-COVERAGE",
                "INV-REBUILD-STABLE",
                "INV-SOURCES-UNCHANGED",
            ),
        )

    def test_source_integrity_invariant_counts_changes_without_leaking_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unchanged = root / "unchanged.jsonl"
            modified = root / "modified.jsonl"
            removed = root / "removed.jsonl"
            for path in (unchanged, modified, removed):
                path.write_bytes(b"synthetic source\n")
            sources = [str(unchanged), str(modified), str(removed)]
            before = {path: rdr.sha256_of(path) for path in sources}

            modified.write_bytes(b"synthetic source changed\n")
            removed.unlink()
            verdict = rdr._source_integrity_invariant(sources, before)

            self.assertEqual(verdict["id"], "INV-SOURCES-UNCHANGED")
            self.assertFalse(verdict["passed"])
            self.assertEqual(
                verdict["detail"],
                "3 sources checked, 1 unchanged, 2 changed",
            )
            for path in sources:
                self.assertNotIn(path, verdict["detail"])

    def test_outcome_is_failed_when_any_invariant_fails(self):
        # build_report derives outcome from the verdicts: one failure is enough.
        passing = [rdr.invariant(id_, True, "fine") for id_ in rdr.INVARIANT_IDS]
        self.assertEqual(sample_report(passing)["outcome"], "passed")
        mixed = passing[:-1] + [
            rdr.invariant("INV-SPAN-COVERAGE", False, "byte coverage 0.5 of 1.0")
        ]
        self.assertEqual(sample_report(mixed)["outcome"], "failed")

    def test_zero_placement_context_is_expected_to_be_empty(self):
        self.assertTrue(
            rdr._is_zero_placement_context(
                {"messages": [], "session": {"messages": []}}
            )
        )
        self.assertFalse(
            rdr._is_zero_placement_context(
                {"messages": [], "session": {"messages": ["msg_v1_synthetic"]}}
            )
        )
        self.assertFalse(rdr._is_zero_placement_context({"messages": []}))

    def test_validate_report_accepts_the_canonical_shape(self):
        self.assertEqual(rdr.validate_report(sample_report()), [])

    def test_validate_report_names_missing_invariants_and_bad_outcome(self):
        report = sample_report()
        report["invariants"] = [entry for entry in report["invariants"] if entry["id"] != "INV-SPAN-COVERAGE"]
        report["outcome"] = "maybe"
        problems = rdr.validate_report(report)
        self.assertIn("missing invariant: INV-SPAN-COVERAGE", problems)
        self.assertIn("outcome must be passed or failed", problems)

    def test_validate_report_names_missing_top_level_fields(self):
        report = sample_report()
        del report["corpus"]
        self.assertIn("missing field: corpus", rdr.validate_report(report))

    def test_validate_report_rejects_unexpected_top_level_fields(self):
        # 字段集是闭的：未知顶层字段可能携带未脱敏的敏感数据，必须拒绝。
        report = sample_report()
        report["unexpected_sensitive_field"] = "secret"
        problems = rdr.validate_report(report)
        self.assertIn("unexpected field: unexpected_sensitive_field", problems)
        self.assertEqual(len(problems), 1)

    def test_report_carries_a_basename_never_a_directory(self):
        # The privacy contract allows the binary's basename only — no directory
        # component may reach the report, so an absolute path must not survive.
        report = sample_report()
        self.assertNotIn(os.sep, report["binary"]["path_basename"])
        self.assertEqual(
            os.path.basename(report["binary"]["path_basename"]),
            report["binary"]["path_basename"],
        )

    def test_markdown_projection_covers_every_invariant(self):
        report = sample_report()
        markdown = rdr.render_markdown(report)
        for invariant_id in rdr.INVARIANT_IDS:
            self.assertIn(invariant_id, markdown)
        self.assertIn(report["outcome"], markdown)


class EndToEndTests(unittest.TestCase):
    """Full harness run against synthetic fixtures and the real binary."""

    @classmethod
    def setUpClass(cls):
        cls.binary = locate_binary()
        if cls.binary is None:
            raise unittest.SkipTest(
                "release binary not found; run "
                "cargo build --locked --release -p agent-session-grep-cli "
                "or set AGENT_SESSION_GREP_BINARY"
            )

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="rdr-test-"))
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.corpus = self.workdir / "corpus"
        self.corpus.mkdir()
        write_fixture(
            self.corpus / "one.jsonl",
            "aaaa1111-2222-4333-8444-555566667771",
            "alpha",
        )
        write_reparented_fixture(
            self.corpus / "two.jsonl",
            "bbbb1111-2222-4333-8444-555566667772",
            "aaaa1111-2222-4333-8444-555566667772",
            f"{SECRET_TOKEN} reply alpha",
            "beta",
        )

    def run_harness(self, *extra):
        out = self.workdir / "report.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent / "real_data_regression.py"),
                "--binary",
                str(self.binary),
                "--sources",
                str(self.corpus),
                "--out",
                str(out),
                *extra,
            ],
            capture_output=True,
            text=True,
        )
        return completed, out

    def test_synthetic_corpus_passes_every_invariant(self):
        completed, out = self.run_harness()
        self.assertEqual(
            completed.returncode,
            0,
            f"harness failed\nstdout: {completed.stdout}\nstderr: {completed.stderr}",
        )
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["outcome"], "passed", report["invariants"])
        reported = [entry["id"] for entry in report["invariants"]]
        self.assertEqual(reported, list(rdr.INVARIANT_IDS))
        source_integrity = next(
            item
            for item in report["invariants"]
            if item["id"] == "INV-SOURCES-UNCHANGED"
        )
        self.assertTrue(source_integrity["passed"], source_integrity)
        self.assertEqual(
            source_integrity["detail"],
            "2 sources checked, 2 unchanged, 0 changed",
        )
        self.assertEqual(report["corpus"]["source_files"], 2)
        # Six emitted occurrences include one stable Message reused/re-parented
        # in the second session, so the stable entity census is five.
        self.assertEqual(report["totals"]["messages"], 5)
        self.assertEqual(report["totals"]["sessions"], 2)
        self.assertEqual(report["evidence_precision"]["unknown"], 0)
        no_loss = next(
            item
            for item in report["invariants"]
            if item["id"] == "INV-NO-PARSE-LOSS"
        )
        self.assertTrue(no_loss["passed"], no_loss)
        self.assertIn("emitted 6", no_loss["detail"])
        self.assertIn("persisted 6 source-placement claims", no_loss["detail"])
        self.assertIn("skipped 0", no_loss["detail"])

    def test_report_never_contains_corpus_text(self):
        _, out = self.run_harness()
        serialized = out.read_text(encoding="utf-8")
        self.assertNotIn(SECRET_TOKEN, serialized)
        # Source paths and provider-native ids must not leak either.
        self.assertNotIn("one.jsonl", serialized)
        self.assertNotIn(str(self.corpus), serialized)
        self.assertNotIn("aaaa1111", serialized)
        markdown = out.with_suffix(".md")
        if markdown.is_file():
            markdown_text = markdown.read_text(encoding="utf-8")
            self.assertNotIn(SECRET_TOKEN, markdown_text)
            self.assertNotIn("aaaa1111", markdown_text)

    def test_dry_run_writes_nothing(self):
        completed, out = self.run_harness("--dry-run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(out.exists(), "dry run must not write a report")

    def test_empty_source_selection_is_a_usage_error(self):
        empty = self.workdir / "empty"
        empty.mkdir()
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent / "real_data_regression.py"),
                "--binary",
                str(self.binary),
                "--sources",
                str(empty),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
