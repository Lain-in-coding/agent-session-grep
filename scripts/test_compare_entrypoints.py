#!/usr/bin/env python3
"""Unit tests for entry-point projection and verdict rules."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parent / "rehearsal" / "compare_entrypoints.py"
SPEC = importlib.util.spec_from_file_location("compare_entrypoints", SCRIPT)
assert SPEC and SPEC.loader
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


class CompareEntrypointsTests(unittest.TestCase):
    def test_unimplemented_surface_is_not_a_pass(self) -> None:
        results = {
            "cli": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "mcp": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "robot": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "web": {"status": "not_implemented", "reason": "serve endpoint unavailable"},
            "tui": {"status": "not_implemented", "reason": "snapshot unavailable"},
        }
        result = compare.compare_canonical("search", results)
        self.assertEqual(result["verdict"], "not_implemented")

    def test_matching_views_are_consistent(self) -> None:
        results = {
            "cli": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "mcp": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "robot": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "web": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "tui": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
        }
        result = compare.compare_canonical("search", results)
        self.assertEqual(result["verdict"], "consistent")
        self.assertEqual(
            result["compared"], ["cli", "mcp", "robot", "web", "tui"]
        )

    def test_divergent_hit_ids_are_reported(self) -> None:
        results = {
            "cli": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}},
            "web": {"outcome": "success", "data": {"hits": [{"id": "msg_v1_b"}]}, "page": {"has_more": False}},
        }
        result = compare.compare_canonical("search", results)
        self.assertEqual(result["verdict"], "divergent")
        self.assertEqual(len(result["divergences"]), 1)

    def test_web_projection_uses_bearer_and_loopback_host(self) -> None:
        response = mock.MagicMock()
        with mock.patch.object(compare.urllib.request, "urlopen", return_value=response) as opener:
            response.__enter__.return_value.status = 200
            response.__enter__.return_value.read.return_value = b'{"outcome":"success"}'
            payload = compare.web_get("http://127.0.0.1:1234", "/api/projection/search?q=x", "synthetic-token")
        self.assertEqual(payload["outcome"], "success")
        headers = opener.call_args.args[0].headers
        self.assertEqual(headers["Authorization"], "Bearer synthetic-token")
        self.assertEqual(headers["Host"], "127.0.0.1")

    def test_all_entry_points_are_declared_implemented(self) -> None:
        self.assertEqual(compare.IMPLEMENTED_ENTRY_POINTS, compare.ENTRY_POINTS)

    def test_empty_hits_everywhere_is_not_a_pass(self) -> None:
        """Agreement on nothing is not consistency: an empty hit list is
        identical across every entry point, so a broken fixture, ingest, or
        query path must not be reported as agreement."""
        empty = {"outcome": "success", "data": {"hits": []}, "page": {"has_more": False}}
        results = {entry_point: dict(empty) for entry_point in compare.ENTRY_POINTS}
        result = compare.compare_canonical("search", results)
        self.assertEqual(result["verdict"], "vacuous")
        self.assertEqual(
            [entry["field"] for entry in result["divergences"]], ["data.hits[*].id"]
        )

    def test_field_absent_from_every_projection_is_not_a_pass(self) -> None:
        absent = {"data": {"hits": [{"id": "msg_v1_a"}]}, "page": {"has_more": False}}
        results = {entry_point: dict(absent) for entry_point in compare.ENTRY_POINTS}
        result = compare.compare_canonical("search", results)
        self.assertEqual(result["verdict"], "vacuous")
        self.assertEqual([entry["field"] for entry in result["divergences"]], ["outcome"])

    def test_overall_verdict_names_the_failing_verdict(self) -> None:
        report = compare.build_report(
            "synthetic-binary", [{"verdict": "vacuous", "operation": "search"}]
        )
        self.assertEqual(report["overall_verdict"], "vacuous")


if __name__ == "__main__":
    unittest.main()
