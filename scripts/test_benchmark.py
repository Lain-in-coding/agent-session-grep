#!/usr/bin/env python3
"""Unit tests for the benchmark harness's asg CLI invocations."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("benchmark.py")
SPEC = importlib.util.spec_from_file_location("benchmark", SCRIPT)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class BenchmarkSearchLatencyTests(unittest.TestCase):
    def test_uses_max_items_not_unsupported_limit_flag(self) -> None:
        seen_args: list[list[str]] = []

        def fake_run_asg(asg_bin: str, data_root: str, args: list[str]):
            seen_args.append(args)
            return 0, '{"data": {"hits": []}}', ""

        with mock.patch.object(benchmark, "run_asg", side_effect=fake_run_asg):
            result = benchmark.benchmark_search_latency(
                "synthetic-asg", "synthetic-root", ["error"]
            )

        self.assertEqual(result["query_count"], 1)
        self.assertEqual(len(seen_args), 1)
        self.assertIn("--max-items", seen_args[0])
        self.assertNotIn("--limit", seen_args[0])


if __name__ == "__main__":
    unittest.main()
