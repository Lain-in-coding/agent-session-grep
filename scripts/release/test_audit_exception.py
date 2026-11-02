"""Prevent removed ZIP vulnerabilities and stale audit exceptions returning."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
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

    def test_audit_policies_have_no_advisory_exceptions(self):
        for name in (".cargo/audit.toml", "deny.toml"):
            with self.subTest(policy=name):
                self.assertEqual(load(name)["advisories"]["ignore"], [])

    def test_all_locked_zip_versions_are_fixed(self):
        versions = {p["version"] for p in self.packages if p["name"] == "zip"}
        self.assertTrue(versions, "the offline bundle verifier must remain covered")
        self.assertEqual(self.vulnerable, set(), "ZIP < 9 requires a dependency fix")

    def test_fixed_candle_stack_remains_optional(self):
        users = dependents(self.packages, "candle-core",
                           {p["version"] for p in self.packages if p["name"] == "candle-core"})
        self.assertIn("agent-session-grep-application", users)
        self.assertLessEqual(users, CANDLE | {"agent-session-grep-application"})
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
