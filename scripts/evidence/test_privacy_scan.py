import importlib.util
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


class RepoScanTests(unittest.TestCase):
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
