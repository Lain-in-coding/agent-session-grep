"""Keep the cargo-audit zip exception in .cargo/audit.toml narrow and current.

The exception is valid only while vulnerable zip (< 9.0.0) is reachable solely
through the optional semantic-candle stack, which release builds never enable.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
ADVISORIES = {"RUSTSEC-2026-0367", "RUSTSEC-2026-0368", "RUSTSEC-2026-0369"}
CANDLE = {"candle-core", "candle-nn", "candle-transformers"}


def load(path: str) -> dict:
    return tomllib.loads((ROOT / path).read_text(encoding="utf-8"))


def major(version: str) -> int:
    return int(version.split(".", 1)[0])


def dependents(packages: list[dict], name: str, wanted: set[str]) -> set[str]:
    """Locked packages that depend on `name` at one of the `wanted` versions."""
    versions = [p["version"] for p in packages if p["name"] == name]
    found = set()
    for package in packages:
        for entry in package.get("dependencies", []):
            parts = entry.split()
            if parts[0] != name:
                continue
            version = parts[1] if len(parts) > 1 else versions[0]
            if version in wanted:
                found.add(package["name"])
    return found


class AuditExceptionTests(unittest.TestCase):
    def setUp(self):
        self.packages = load("Cargo.lock")["package"]
        self.vulnerable = {p["version"] for p in self.packages
                           if p["name"] == "zip" and major(p["version"]) < 9}

    def test_ignore_list_is_exactly_the_zip_extract_advisories(self):
        ignore = load(".cargo/audit.toml")["advisories"]["ignore"]
        self.assertEqual(set(ignore), ADVISORIES)
        self.assertEqual(len(ignore), len(ADVISORIES))

    def test_exception_is_removed_once_no_vulnerable_zip_is_locked(self):
        self.assertTrue(self.vulnerable, "no zip < 9 is locked; delete the ignores in "
                        ".cargo/audit.toml and this test")

    def test_vulnerable_zip_is_reached_only_through_optional_candle(self):
        self.assertEqual(dependents(self.packages, "zip", self.vulnerable), {"candle-core"})
        workspace = {p["name"] for p in self.packages if "source" not in p}
        users = dependents(self.packages, "candle-core",
                           {p["version"] for p in self.packages if p["name"] == "candle-core"})
        self.assertEqual(users & workspace, {"agent-session-grep-application"})
        self.assertLessEqual(users - workspace, CANDLE)
        manifest = load("crates/agent-session-grep-application/Cargo.toml")
        for name in CANDLE:
            self.assertIs(manifest["dependencies"][name]["optional"], True)
        self.assertEqual(manifest["features"]["default"], [])
        cli = load("crates/agent-session-grep-cli/Cargo.toml")
        self.assertEqual(cli["features"]["default"], [])
        self.assertTrue(re.fullmatch(r"=?9\.\d+\.\d+", cli["dependencies"]["zip"]["version"]))

    def test_release_builds_never_enable_semantic_candle(self):
        for name in ("release.yml", "release-verify.yml"):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            builds = re.findall(r"cargo build [^\n]*--release[^\n]*", text)
            self.assertTrue(builds, name)
            for line in builds:
                self.assertIn("--no-default-features", line, name)
                self.assertNotIn("semantic-candle", line, name)


if __name__ == "__main__":
    unittest.main()
