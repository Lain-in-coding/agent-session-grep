"""Verify the exact, offline Candle compatibility patch shipped with this tree."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import unittest

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / "vendor" / "candle-core-0.11.1"
ARCHIVE_SHA256 = "d11c8be87cfbaef9ebb62fb3f850d1fc8e00cc1d11d393fdbe55a4d5c2cdb325"
PROVENANCE_SHA256 = "065f475d3c16f31883d91182b91a3969fe3c2ca9d34c37b61aee81b542a87fff"
CHANGED = {"Cargo.toml", "src/quantized/repack_x86.rs"}
OLD_CPUID = b"            let info = core::arch::x86_64::__cpuid_count(7, 0);"
NEW_CPUID = (
    b"            // SAFETY: CPUID is available on every x86_64 CPU; leaf 7 only reads feature flags.\n"
    b"            #[allow(unused_unsafe)]\n"
    b"            let info = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };"
)


def verify_files(provenance, files):
    if (
        provenance["schema"] != "asg.vendored-library/v1"
        or provenance["package"] != "candle-core"
        or provenance["version"] != "0.11.1"
        or provenance["crate_sha256"] != ARCHIVE_SHA256
        or provenance["upstream_commit"] != "59f8e903ca80a32ea7f8514b39748fc979e69e82"
        or provenance["patch_commit"] != "486cd95a1e53f38719e77129444f0da621086966"
        or set(provenance["changes"]) != CHANGED
    ):
        raise ValueError("unexpected upstream or patch identity")
    records = provenance["files"]
    expected = {}
    changed = set()
    for record in records:
        name = record["path"]
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or name in expected:
            raise ValueError("invalid provenance path")
        expected[name] = record
        if record["sha256"] != record["upstream_sha256"]:
            changed.add(name)
    if len(expected) != 72 or set(files) != set(expected) or changed != CHANGED:
        raise ValueError("vendored library inventory changed")
    for name, content in files.items():
        if hashlib.sha256(content).hexdigest() != expected[name]["sha256"]:
            raise ValueError("vendored file checksum mismatch")
    patched = files["src/quantized/repack_x86.rs"]
    if patched.count(NEW_CPUID) != 1:
        raise ValueError("declared CPUID fix is missing")
    restored = patched.replace(NEW_CPUID, OLD_CPUID, 1)
    if hashlib.sha256(restored).hexdigest() != expected["src/quantized/repack_x86.rs"]["upstream_sha256"]:
        raise ValueError("unlisted Candle source change")
    manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
    if (
        manifest["package"]["name"] != "candle-core"
        or manifest["package"]["version"] != "0.11.1"
        or manifest["package"]["publish"] is not False
        or manifest["dependencies"]["zip"]["version"] != "9.1.3"
        or manifest["features"]["default"] != []
        or any(key in manifest for key in ("dev-dependencies", "example", "test", "bench"))
    ):
        raise ValueError("vendored dependency or target contract changed")
    if b"Apache License" not in files["LICENSE"]:
        raise ValueError("upstream license missing")


class VendoredCandleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = (VENDOR / "UPSTREAM.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != PROVENANCE_SHA256:
            raise AssertionError("reviewed vendored provenance changed")
        cls.provenance = json.loads(raw)
        cls.files = {}
        for path in VENDOR.rglob("*"):
            if path.is_symlink():
                raise AssertionError("vendored source cannot contain links")
            if path.is_file() and path != VENDOR / "UPSTREAM.json":
                cls.files[path.relative_to(VENDOR).as_posix()] = path.read_bytes()

    def test_exact_upstream_library_and_only_reviewed_patch(self):
        verify_files(self.provenance, self.files)

    def test_corrupted_missing_and_extra_files_are_rejected(self):
        for change in ("corrupt", "missing_license", "extra", "nested_provenance", "unlisted_patch"):
            with self.subTest(change=change):
                files = dict(self.files)
                provenance = copy.deepcopy(self.provenance)
                if change == "corrupt":
                    files["src/lib.rs"] += b"\n"
                elif change == "missing_license":
                    del files["LICENSE"]
                elif change == "extra":
                    files["unreviewed.rs"] = b""
                elif change == "nested_provenance":
                    files["nested/UPSTREAM.json"] = b"{}"
                else:
                    name = "src/quantized/repack_x86.rs"
                    files[name] += b"\n"
                    for row in provenance["files"]:
                        if row["path"] == name:
                            row["sha256"] = hashlib.sha256(files[name]).hexdigest()
                with self.assertRaises(ValueError):
                    verify_files(provenance, files)

    def test_override_is_transitive_but_not_a_workspace_member(self):
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            workspace["patch"]["crates-io"]["candle-core"],
            {"path": "vendor/candle-core-0.11.1"},
        )
        self.assertIn("vendor/candle-core-0.11.1", workspace["workspace"]["exclude"])
        self.assertIn(
            "vendor/candle-core-0.11.1/** -text",
            (ROOT / ".gitattributes").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
