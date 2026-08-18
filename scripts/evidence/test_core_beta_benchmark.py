import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("core_beta_benchmark.py")
SPEC = importlib.util.spec_from_file_location("core_beta_benchmark", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


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


if __name__ == "__main__":
    unittest.main()
