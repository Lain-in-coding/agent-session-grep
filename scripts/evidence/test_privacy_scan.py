import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("privacy_scan.py")
SPEC = importlib.util.spec_from_file_location("privacy_scan", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SCANNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCANNER
SPEC.loader.exec_module(SCANNER)

# Reuse the scanner's own fragment-assembled tokens instead of spelling them
# out, so this test file never contains a literal copy of a forbidden token and
# stays clean under the `public` profile it exercises.
TRACKER = SCANNER._TRACKER
CLONE_DIR = SCANNER._CLONE_DIR
CHECKOUT_ROOT = SCANNER._CHECKOUT_ROOT
REFERENCE_ROOT = SCANNER._REFERENCE_ROOT
PRIVATE_OWNER = SCANNER._PRIVATE_OWNER
INTERNAL_INTERVIEW = SCANNER._INTERNAL_INTERVIEW
TASK_ID = "08-15-" + "privacy-hooks"
PUBLIC = SCANNER.PROFILES["public"]


class RuleTests(unittest.TestCase):
    def test_flags_personal_absolute_paths(self) -> None:
        lines = [
            "checkout root " + "C:/" + "Users/Alice/project was scanned",
            "worktree " + "/Users/" + "alice/repo also appears",
            "home directory " + "/home/" + "alice/repo",
            "escaped " + "C:" + "\\\\Users\\\\Alice\\\\transcript.jsonl",
        ]
        findings = SCANNER.scan_lines("notes.md", lines, frozenset())
        self.assertEqual(
            [(f.line, f.rule) for f in findings],
            [(1, "user-home"), (2, "user-home"), (3, "user-home"), (4, "user-home")],
        )

    def test_flags_non_ascii_username_machine_roots_and_worktrees(self) -> None:
        findings = SCANNER.scan_lines(
            "research.md",
            [
                "cache at " + "C:/" + "Users/用户/.cache/tool",
                "checkout at " + "C:/" + CHECKOUT_ROOT + "/crates",
                "reference at " + "D:" + "\\" + REFERENCE_ROOT + "\\project",
                "coordinate " + "." + "claude/worktrees/agent-abc123",
                "branch " + "worktree-" + TASK_ID,
            ],
            frozenset(),
        )
        self.assertEqual(
            [f.rule for f in findings],
            [
                "user-home",
                "machine-root",
                "machine-root",
                "agent-coordinate",
                "agent-coordinate",
            ],
        )

    def test_machine_root_covers_wsl_mount_paths(self) -> None:
        # WSL build transcripts spell the same checkout as /mnt/<drive>/<root>,
        # which the drive-letter form alone would miss.
        findings = SCANNER.scan_lines(
            "build.txt",
            ["Compiling from " + "/mnt/c/" + CHECKOUT_ROOT + "/crates/domain"],
            frozenset(),
        )
        self.assertEqual([f.rule for f in findings], ["machine-root"])

    def test_allowlist_accepts_only_exact_synthetic_entries(self) -> None:
        findings = SCANNER.scan_lines(
            "crates/agent-session-grep-cli/src/protocol.rs",
            ['error "cannot open ' + "C:/" + 'Users/secret/transcript.jsonl"'],
        )
        self.assertEqual(findings, [])

        # Same path shape in a file that is not allowlisted must still flag.
        findings = SCANNER.scan_lines(
            "docs/notes.md",
            ['error "cannot open ' + "C:/" + 'Users/secret/transcript.jsonl"'],
        )
        self.assertEqual(len(findings), 1)

    def test_imported_fixture_allowances_stay_exact(self) -> None:
        fixtures = (
            ("crates/agent-session-grep-cli/src/lib.rs", SCANNER.SLASH_WIN_HOME + "x"),
            ("crates/agent-session-grep-cli/src/lib.rs", SCANNER.WIN_HOME + "x"),
            ("crates/agent-session-grep-cli/src/mcp.rs", SCANNER.SLASH_WIN_HOME + "secret"),
            ("crates/agent-session-grep-provider-pi/tests/golden/v3-branched.jsonl",
             SCANNER.LINUX_HOME + "user"),
        )
        for path, value in fixtures:
            with self.subTest(path=path, value=value):
                self.assertEqual(SCANNER.scan_lines(path, [value], rules=PUBLIC), [])
                self.assertEqual(len(SCANNER.scan_lines(
                    path + ".other", [value], rules=PUBLIC)), 1)
                self.assertEqual(len(SCANNER.scan_lines(
                    path, [value + "-other"], rules=PUBLIC)), 1)
                other_rule = (("other-rule", "synthetic", SCANNER.re.compile(
                    SCANNER.re.escape(value))),)
                self.assertEqual(len(SCANNER.scan_lines(
                    path, [value], rules=other_rule)), 1)

    def test_synthetic_non_personal_roots_do_not_match(self) -> None:
        # C:/data and C:/profiles style fixtures are not user homes; the
        # scanner deliberately does not reject generic drive roots.
        findings = SCANNER.scan_lines(
            "docs/runbook.md",
            ["use --db C:/data/example.db and fixture C:/profiles/one"],
            frozenset(),
        )
        self.assertEqual(findings, [])

    def test_decode_text_skips_binary_and_utf16(self) -> None:
        self.assertIsNone(SCANNER.decode_text(b"a\x00b"))
        self.assertIsNone(SCANNER.decode_text("abc".encode("utf-16-le")))
        self.assertEqual(SCANNER.decode_text("abc".encode("utf-8")), "abc")


class PublicProfileTests(unittest.TestCase):
    """The `public` profile adds internal-leak rules on top of the base set."""

    def test_flags_internal_tracker_task_ids_clone_dir_and_private_repo(self) -> None:
        findings = SCANNER.scan_lines(
            "docs/roadmap.md",
            [
                "see ." + TRACKER + "/tasks/x/prd.md",
                "delivered by " + TASK_ID,
                "surveyed under " + CLONE_DIR + "/reference",
                "advisory at github.com/" + PRIVATE_OWNER + "/" + CHECKOUT_ROOT,
                "confirmed in an " + INTERNAL_INTERVIEW + " session",
            ],
            frozenset(),
            rules=PUBLIC,
        )
        self.assertEqual(
            [f.rule for f in findings],
            [
                "internal-tracker",
                "internal-task-id",
                "reference-clone-dir",
                "private-repo-slug",
                "internal-tracker",
            ],
        )

    def test_base_profile_ignores_internal_leaks(self) -> None:
        # The development checkout tracks the tracker directory on purpose, so
        # the default profile must not reject references to it.
        findings = SCANNER.scan_lines(
            "docs/roadmap.md",
            ["see ." + TRACKER + "/tasks/" + TASK_ID + "/prd.md"],
            frozenset(),
        )
        self.assertEqual(findings, [])

    def test_provider_directories_are_not_internal_leaks(self) -> None:
        # Provider transcript locations must stay nameable: this tool exists to
        # read them, so the public profile deliberately does not match them.
        findings = SCANNER.scan_lines(
            "README.md",
            [
                "reads ~/.claude/projects and ~/.codex/sessions",
                "and ~/.codebuddy/history",
            ],
            frozenset(),
            rules=PUBLIC,
        )
        self.assertEqual(findings, [])

    def test_dates_and_versions_are_not_task_ids(self) -> None:
        # The task-id rule needs a two-or-more-word slug, so ISO dates,
        # semantic versions, and single-word hyphenations do not match.
        findings = SCANNER.scan_lines(
            "CHANGELOG.md",
            [
                "released 2026-08-15 as v0.1.0",
                "schema 12-31-x and range 01-02-03",
                "profile 08-15-beta names one word only",
            ],
            frozenset(),
            rules=PUBLIC,
        )
        self.assertEqual(findings, [])

    def test_scanner_and_its_test_are_clean_under_public_profile(self) -> None:
        # Both files describe the forbidden tokens; assembling them from
        # fragments is what keeps the scanner able to scan itself.
        for path in (MODULE_PATH, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            findings = SCANNER.scan_lines(
                path.name, text.splitlines(), frozenset(), rules=PUBLIC
            )
            self.assertEqual(findings, [], f"{path.name} leaks a forbidden token")


class HistoricalSnapshotTests(unittest.TestCase):
    # Independent pins: tests must not silently adopt an edited registry.
    SNAPSHOTS = (
        ("docs/operations/imports/public-tree-v1-"
         "e0f26822ff2383e0017a7054ecc1acf8d18830bd57cb32e99c5d64155f8568af.json",
         "e0f26822ff2383e0017a7054ecc1acf8d18830bd57cb32e99c5d64155f8568af",
         "agent-session-grep.public-tree/v1", frozenset({"excluded_prefixes"})),
        ("docs/operations/imports/public-tree-v2-f587c73332158342330a63874fabdc8f565624ec.json",
         "121e09c2ab6f7e5922a0862ea095fae3ae343913847cc3efa62546cf71585ead",
         "agent-session-grep.public-tree/v2", frozenset({"excluded_prefixes", "profile"})),
    )

    def original(self, path: str) -> bytes:
        return (MODULE_PATH.parents[2] / path).read_bytes()

    def test_registry_matches_reviewed_paths_bytes_schemas_and_fields(self) -> None:
        expected = {path: (digest, schema, fields)
                    for path, digest, schema, fields in self.SNAPSHOTS}
        self.assertEqual(dict(SCANNER.HISTORICAL_SNAPSHOTS), expected)
        for path, digest, schema, _ in self.SNAPSHOTS:
            raw = self.original(path)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            self.assertEqual(json.loads(raw)["schema"], schema)
            for profile in SCANNER.PROFILES:
                with self.subTest(path=path, profile=profile):
                    self.assertEqual(SCANNER.scan_content(path, raw, profile), [])
        with self.assertRaises(TypeError):
            SCANNER.HISTORICAL_SNAPSHOTS["other.json"] = self.SNAPSHOTS[0][1:]

    def test_projection_preserves_every_nonpolicy_field_and_inventory(self) -> None:
        for path, _, _, omitted in self.SNAPSHOTS:
            raw = self.original(path)
            with mock.patch.object(SCANNER, "scan_lines", wraps=SCANNER.scan_lines) as scan:
                self.assertEqual(SCANNER.scan_content(path, raw, "public"), [])
            # The common content scanner scans one complete JSON projection;
            # no inventory record or nested namesake field may disappear.
            projected = json.loads("\n".join(scan.call_args.args[1]))
            original = json.loads(raw)
            self.assertEqual(projected, {k: v for k, v in original.items() if k not in omitted})
            self.assertEqual(projected["files"], original["files"])
            self.assertTrue(SCANNER.scan_lines(path, raw.decode().splitlines(), rules=PUBLIC))

    def test_byte_hash_path_schema_and_encoding_mutations_fail_closed(self) -> None:
        for path, _, _, _ in self.SNAPSHOTS:
            raw = self.original(path)
            changed_schema = json.loads(raw)
            changed_schema["schema"] = "unrecognized"
            mutations = [raw + b" ", raw.replace(b"\n", b"\r\n"), b"{}", b"null",
                         b"not json", b"\x00", b"\xff", json.dumps(changed_schema).encode()]
            for profile in SCANNER.PROFILES:
                for data in mutations:
                    with self.subTest(path=path, profile=profile, size=len(data)):
                        hits = SCANNER.scan_content(path, data, profile)
                        self.assertIn("snapshot-integrity", [f.rule for f in hits])
                for changed_path in (path + ".other", path.upper(), "moved.json",
                                     "other/" + path, path.replace("public-tree-", "public-tree-edited-"),
                                     "PUBLIC-TREE-MANIFEST.json"):
                    hits = SCANNER.scan_content(changed_path, raw, profile)
                    self.assertIn("unregistered-snapshot", [f.rule for f in hits])

    def test_schema_is_checked_even_after_digest_verification(self) -> None:
        # Isolate the schema guard; real-byte mutations are rejected above.
        for path, digest, _, _ in self.SNAPSHOTS:
            data = json.loads(self.original(path))
            data["schema"] = "agent-session-grep.public-tree/v99"
            raw = json.dumps(data).encode()
            with mock.patch.object(SCANNER.hashlib, "sha256") as sha:
                sha.return_value.hexdigest.return_value = digest
                hits = SCANNER.scan_content(path, raw, "public")
            self.assertIn("snapshot-integrity", [f.rule for f in hits])

    def test_unregistered_pattern_free_snapshots_are_not_ordinary_json(self) -> None:
        unknown = "docs/operations/imports/public-tree-v99-unknown.json"
        for raw in (b"{}", b"not json", b"\x00", b"[]"):
            self.assertEqual([f.rule for f in SCANNER.scan_content(unknown, raw)],
                             ["unregistered-snapshot"])
        for schema in ("agent-session-grep.public-tree/v1", "agent-session-grep.public-tree/v2"):
            raw = json.dumps({"schema": schema, "files": [], "sha256": "0" * 64,
                              "registry": {"allow": True}}).encode()
            self.assertEqual([f.rule for f in SCANNER.scan_content("renamed.txt", raw)],
                             ["unregistered-snapshot"])
        self.assertEqual([f.rule for f in SCANNER.scan_content("PUBLIC-TREE-MANIFEST.json", b"{}")],
                         ["unregistered-snapshot"])
        with self.assertRaises(TypeError):
            SCANNER.scan_content(unknown, b"{}", registry={unknown: "allow"})

    def test_injected_metadata_and_inventory_cannot_inherit_a_pin(self) -> None:
        for path, digest, _, omitted in self.SNAPSHOTS:
            for key in dict.fromkeys((*json.loads(self.original(path)), "profile", "notes", "extra")):
                data = json.loads(self.original(path))
                data[key] = {"profile": {"excluded_prefixes": ["." + TRACKER + "/private"]}}
                if key == "schema":
                    continue  # Independently exercised above.
                raw = json.dumps(data).encode()
                hits = SCANNER.scan_content(path, raw, "public")
                self.assertIn("snapshot-integrity", [f.rule for f in hits])
                # Isolate projection from the already-tested digest gate. Even
                # a verified object can omit ONLY the exact top-level fields.
                with mock.patch.object(SCANNER.hashlib, "sha256") as sha:
                    sha.return_value.hexdigest.return_value = digest
                    hits = SCANNER.scan_content(path, raw, "public")
                self.assertEqual("internal-tracker" in [f.rule for f in hits], key not in omitted)

    def test_ordinary_content_and_fixture_triples_still_use_existing_rules(self) -> None:
        value = "." + TRACKER + "/private"
        raw = json.dumps({"profile": value, "excluded_prefixes": [value]}).encode()
        self.assertEqual(SCANNER.scan_content("ordinary.json", raw), [])
        self.assertEqual(len(SCANNER.scan_content("ordinary.json", raw, "public")), 2)
        self.assertEqual(SCANNER.scan_content("image.bin", b"\x00"), [])
        synthetic = (SCANNER.SLASH_WIN_HOME + "secret").encode()
        self.assertEqual(SCANNER.scan_content("crates/agent-session-grep-cli/src/protocol.rs",
                                              synthetic, "public"), [])
        self.assertEqual(len(SCANNER.scan_content("ordinary.txt", synthetic, "public")), 1)

    def test_repo_uses_shared_content_policy_and_safe_cli_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            paths = []
            for path, _, _, _ in self.SNAPSHOTS:
                target = repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(self.original(path))
                paths.append(path)
            subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false", "add", "--", *paths],
                           check=True, capture_output=True)
            self.assertEqual(SCANNER.scan_repo(repo, "public"), [])
            (repo / paths[0]).write_bytes(b"{}")
            hits = SCANNER.scan_repo(repo, "public")
            self.assertEqual([f.rule for f in hits], ["snapshot-integrity"])
            # Missing tracked files are errors, never a coverage exclusion.
            (repo / paths[0]).rename(repo / "retired.json")
            with self.assertRaises(FileNotFoundError):
                SCANNER.scan_repo(repo, "public")
            with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(SCANNER.main(["--repo", str(repo), "--profile", "public"]), 2)
            self.assertNotIn(str(repo), stderr.getvalue())
        private = SCANNER.Finding("private-location.txt", 1, "user-home",
                                  SCANNER.SLASH_WIN_HOME + "Alice", "private excerpt")
        with mock.patch.object(SCANNER, "scan_repo", return_value=[private]), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(SCANNER.main(["--repo", ".", "--profile", "public"]), 1)
        self.assertNotIn(private.path, stderr.getvalue())
        self.assertNotIn(private.match, stderr.getvalue())
        self.assertNotIn(private.excerpt, stderr.getvalue())


class RepoScanTests(unittest.TestCase):
    def test_shared_scan_checks_relative_paths_once_even_for_binary(self) -> None:
        cases = (
            ("docs/" + TASK_ID + ".txt", b"ordinary text", "public", "internal-task-id"),
            ("docs/" + TASK_ID + ".bin", b"\x00", "public", "internal-task-id"),
            ("docs/" + TASK_ID + ".txt", b"ordinary text", "repo", None),
            ("docs-" + SCANNER.LINUX_HOME + "example/note.txt", b"ordinary text",
             "repo", "user-home"),
        )
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            for relative, raw, profile, rule in cases:
                with self.subTest(profile=profile, binary=b"\x00" in raw, rule=rule):
                    target = repo / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)
                    expected = [] if rule is None else [rule]
                    self.assertEqual([f.rule for f in SCANNER.scan_content(relative, raw, profile)],
                                     expected)
                    with mock.patch.object(SCANNER, "tracked_files", return_value=[relative]):
                        self.assertEqual([f.rule for f in SCANNER.scan_repo(repo, profile)], expected)

    def test_tracked_files_returns_every_git_reported_path(self) -> None:
        listing = b"\0".join(
            [
                b"README.md",
                b".claude/settings.json",
                b"target/debug/notes.md",
                b"target-aarch64/notes.md",
                (CLONE_DIR + "/reference/notes.md").encode("utf-8"),
                b"docs/with space.md",
            ]
        )
        completed = subprocess.CompletedProcess(
            args=["git", "ls-files", "-z"], returncode=0, stdout=listing + b"\0"
        )
        with mock.patch.object(SCANNER.subprocess, "run", return_value=completed):
            paths = SCANNER.tracked_files(Path("."))
        self.assertEqual(
            paths,
            [
                "README.md",
                ".claude/settings.json",
                "target/debug/notes.md",
                "target-aarch64/notes.md",
                CLONE_DIR + "/reference/notes.md",
                "docs/with space.md",
            ],
        )

    def test_scan_repo_reads_only_tracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            (repo / "tracked.md").write_text(
                "cache at " + "C:/" + "Users/Alice/.cache/tool\n", encoding="utf-8"
            )
            (repo / "untracked.md").write_text(
                "cache at " + "C:/" + "Users/Bob/.cache/tool\n", encoding="utf-8"
            )
            (repo / "image.bin").write_bytes(b"\x00\x01\x02")

            with mock.patch.object(
                SCANNER, "tracked_files", return_value=["tracked.md", "image.bin"]
            ):
                findings = SCANNER.scan_repo(repo)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "tracked.md")
        self.assertEqual(findings[0].match, "C:/" + "Users/Alice")

    def test_scan_repo_applies_the_requested_profile(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            (repo / "notes.md").write_text(
                "see ." + TRACKER + "/tasks/x/prd.md\n", encoding="utf-8"
            )
            with mock.patch.object(SCANNER, "tracked_files", return_value=["notes.md"]):
                self.assertEqual(SCANNER.scan_repo(repo), [])
                public = SCANNER.scan_repo(repo, "public")
        self.assertEqual([f.rule for f in public], ["internal-tracker"])

    def test_scan_repo_does_not_skip_internal_or_generated_prefixes(self) -> None:
        # A path under an internal/generated directory only reaches this
        # function when it is explicitly tracked (e.g. force-added). Tracked
        # means public, so the scanner must read it instead of filtering the
        # prefix away.
        forced = [
            ".claude/settings.json",
            "target/debug/notes.md",
            "target-aarch64/notes.md",
            CLONE_DIR + "/reference/notes.md",
        ]
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            for relative in forced:
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "cache at " + "C:/" + "Users/Alice/.cache/tool\n", encoding="utf-8"
                )

            with mock.patch.object(SCANNER, "tracked_files", return_value=forced):
                findings = SCANNER.scan_repo(repo)

        self.assertEqual([f.path for f in findings], forced)
        self.assertTrue(all(f.rule == "user-home" for f in findings))

    def test_main_exit_codes(self) -> None:
        with mock.patch.object(SCANNER, "scan_repo", return_value=[]):
            self.assertEqual(SCANNER.main(["--repo", "."]), 0)
        finding = SCANNER.Finding(
            path="x.md", line=1, rule="user-home", match="/" + "home/alice", excerpt=""
        )
        with mock.patch.object(SCANNER, "scan_repo", return_value=[finding]):
            self.assertEqual(SCANNER.main(["--repo", "."]), 1)

    def test_main_rejects_unknown_profile(self) -> None:
        with self.assertRaises(SystemExit):
            SCANNER.main(["--repo", ".", "--profile", "nonexistent"])


if __name__ == "__main__":
    unittest.main()
