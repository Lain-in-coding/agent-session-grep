"""Unit tests for the semantic MCP latency harness honesty contracts.

The harness must refuse to emit latency numbers unless the search envelope
proves the semantic path executed cleanly, and percentile() must implement
nearest-rank semantics (a past off-by-one turned p95 into p90). The tests
never invoke the compiled binary or read a database.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("semantic_mcp_latency.py")
SPEC = importlib.util.spec_from_file_location("semantic_mcp_latency", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class PercentileTest(unittest.TestCase):
    def test_p50_of_odd_count_is_the_median(self) -> None:
        self.assertEqual(MOD.percentile([1.0, 2.0, 3.0], 0.50), 2.0)

    def test_p50_of_even_count_is_the_lower_middle_value(self) -> None:
        # Nearest rank: ceil(0.50 * 4) = 2, so the second sorted value.
        self.assertEqual(MOD.percentile([1.0, 2.0, 3.0, 4.0], 0.50), 2.0)

    def test_p95_is_not_p90(self) -> None:
        samples = [float(i) for i in range(1, 11)]
        self.assertEqual(MOD.percentile(samples, 0.50), 5.0)
        self.assertEqual(MOD.percentile(samples, 0.95), 10.0)


class CheckSemanticEnvelopeTest(unittest.TestCase):
    @staticmethod
    def envelope(
        outcome: str = "success",
        retrieval_mode: str = "semantic",
        warnings: list[str] | None = None,
    ) -> dict:
        return {"outcome": outcome, "data": {"retrieval_mode": retrieval_mode}, "warnings": warnings or []}

    def test_accepts_a_clean_semantic_envelope(self) -> None:
        MOD.check_semantic_envelope(self.envelope())

    def test_refuses_lexical_fallback(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "retrieval_mode=lexical_fallback"):
            MOD.check_semantic_envelope(self.envelope(retrieval_mode="lexical_fallback"))

    def test_refuses_failed_outcome(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "probe search failed"):
            MOD.check_semantic_envelope(self.envelope(outcome="partial"))

    def test_refuses_envelope_with_warnings(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "warnings=\\['degraded'\\]"):
            MOD.check_semantic_envelope(self.envelope(warnings=["degraded"]))


if __name__ == "__main__":
    unittest.main()
