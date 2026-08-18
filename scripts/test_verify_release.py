#!/usr/bin/env python3
"""Unit tests for the synthetic release verifier."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("verify-release.py")
SPEC = importlib.util.spec_from_file_location("verify_release", SCRIPT)
assert SPEC and SPEC.loader
verify_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_release)


class VerifyReleaseTests(unittest.TestCase):
    def test_main_resolves_relative_binary_before_temporary_workdir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            binary = Path(temp_name) / ("asg.exe" if os.name == "nt" else "asg")
            binary.write_text("synthetic binary", encoding="utf-8")
            expected = str(binary.resolve())
            seen: list[str] = []

            def passed(binary_arg: str, *unused: object) -> bool:
                seen.append(binary_arg)
                return True

            checks = [
                "verify_build",
                "verify_sync",
                "verify_search",
                "verify_get",
                "verify_context",
                "verify_resume",
                "verify_handoff",
                "verify_semantic",
                "verify_hook",
                "verify_providers",
            ]
            patches = [mock.patch.object(verify_release, name, passed) for name in checks]
            for patcher in patches:
                patcher.start()
            try:
                with mock.patch("sys.argv", [str(SCRIPT), "--asg", str(binary)]):
                    self.assertEqual(verify_release.main(), 0)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
            self.assertEqual(seen, [expected] * len(checks))

    def test_semantic_check_requires_bigram_hash_and_effective_modes(self) -> None:
        frames = iter(
            [
                {"data": {"model_id": "bigram-hash-v1", "dimension": 384, "indexed": 2}},
                {"retrieval_mode": "semantic", "data": {"hits": [{"id": "msg_v1_s"}]}},
                {"retrieval_mode": "hybrid", "data": {"hits": [{"id": "msg_v1_h"}]}},
            ]
        )
        with mock.patch.object(verify_release, "run_asg", side_effect=lambda *args, **kwargs: next(frames)):
            self.assertTrue(verify_release.verify_semantic("synthetic-binary", "synthetic-root"))

    def test_handoff_requires_schema_10_and_deterministic_pack(self) -> None:
        frames = iter(
            [
                {"data": {"schema_version": "1.0", "pack_id": "pack_v1_abc", "evidence": [{"message_id": "msg_v1_a"}], "inference": []}},
                {"data": {"schema_version": "1.0", "pack_id": "pack_v1_abc", "evidence": [{"message_id": "msg_v1_a"}], "inference": []}},
            ]
        )
        with mock.patch.object(verify_release, "run_asg", side_effect=lambda *args, **kwargs: next(frames)):
            self.assertTrue(verify_release.verify_handoff("synthetic-binary", "synthetic-root"))

        frames = iter(
            [
                {"data": {"schema_version": "handoff-pack/v1", "pack_id": "pack_v1_abc", "evidence": [{"message_id": "msg_v1_a"}], "inference": []}},
                {"data": {"schema_version": "handoff-pack/v1", "pack_id": "pack_v1_abc", "evidence": [{"message_id": "msg_v1_a"}], "inference": []}},
            ]
        )
        with mock.patch.object(verify_release, "run_asg", side_effect=lambda *args, **kwargs: next(frames)):
            self.assertFalse(verify_release.verify_handoff("synthetic-binary", "synthetic-root"))

    def test_hook_default_check_rejects_nonempty_context(self) -> None:
        frame = {
            "data": {
                "enabled": False,
                "hookSpecificOutput": {"additionalContext": "unexpected history"},
            }
        }
        with mock.patch.object(verify_release, "run_asg", return_value=frame):
            self.assertFalse(verify_release.verify_hook("synthetic-binary", "synthetic-root"))

    def test_parse_first_json_line_ignores_blank_lines(self) -> None:
        self.assertEqual(
            verify_release.parse_first_json_line('\n{"data":{"value":1}}\n'),
            {"data": {"value": 1}},
        )


if __name__ == "__main__":
    unittest.main()
