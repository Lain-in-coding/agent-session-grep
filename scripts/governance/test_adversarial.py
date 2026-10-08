"""Adversarial policy, Git object, hook and sanitized CLI tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from common import GateError, GitRepo, parse_json
from check_pr import validate_event
from local_hook import install
from policy import validate_message, validate_identity
from test_policy import GitFixture, GOOD

ROOT = Path(__file__).resolve().parent


class AdversarialTests(GitFixture):
    def test_merge_commit_is_not_ignored(self):
        self.git("checkout", "-q", "-b", "side")
        side = self.commit("side", "side")
        self.git("checkout", "-q", "-b", "main-test", self.base)
        self.commit("main-file", "main")
        self.git("merge", "--no-ff", "-q", "-m", "Merge default text", side)
        head = self.git("rev-parse", "HEAD")
        commits = GitRepo(self.repo).range(self.base, head)
        self.assertEqual(len(commits), 3)
        with self.assertRaises(GateError):
            validate_event(self.event(head), repo=GitRepo(self.repo))

    def test_distinct_author_and_committer_are_preserved(self):
        (self.repo / "external").write_text("External contribution")
        self.git("add", "external")
        self.git("commit", "-q", "--author=External Human <external@example.org>", "-m", GOOD)
        head = self.git("rev-parse", "HEAD")
        commit = GitRepo(self.repo).range(self.base, head)[0]
        self.assertEqual(commit.author["name"], "External Human")
        self.assertEqual(commit.committer["name"], "Synthetic Human")
        validate_event(self.event(head), repo=GitRepo(self.repo))

    def test_tool_like_human_and_authorized_bot_metadata_are_preserved(self):
        self.git("config", "user.name", "copilot[bot]")
        self.git("config", "user.email", "copilot@github.com")
        (self.repo / "human").write_text("External contribution")
        self.git("add", "human")
        self.git("commit", "-q", "--author=Claude <claude@example.org>", "-m", GOOD)
        head = self.git("rev-parse", "HEAD")
        commit = GitRepo(self.repo).range(self.base, head)[0]
        self.assertEqual(commit.author, {"name": "Claude", "email": "claude@example.org"})
        self.assertEqual(commit.committer, {"name": "copilot[bot]", "email": "copilot@github.com"})
        validate_event(self.event(head), repo=GitRepo(self.repo), merge_message=GOOD,
                       merge_metadata={"author": commit.author, "committer": commit.committer})

    def test_offline_git_protocol_cannot_be_reenabled_by_local_config(self):
        self.git("config", "protocol.file.allow", "always")
        # Exercise the actual Git transport denial, without any network request.
        with self.assertRaisesRegex(GateError, "git-evidence-incomplete"):
            GitRepo(self.repo).git("ls-remote", str(self.repo))

    def test_partial_clone_and_grafts_reject(self):
        self.git("config", "remote.origin.promisor", "true")
        with self.assertRaises(GateError):
            GitRepo(self.repo)
        self.git("config", "--unset", "remote.origin.promisor")
        info = self.repo / ".git" / "info"
        info.mkdir(exist_ok=True)
        (info / "grafts").write_text(self.base + "\n")
        with self.assertRaises(GateError):
            GitRepo(self.repo)

    def test_replaced_graph_rejects(self):
        head = self.commit("one", "one")
        self.git("replace", head, self.base)
        with self.assertRaises(GateError):
            GitRepo(self.repo)

    def test_missing_blob_rejects(self):
        head = self.commit("one", "one")
        oid = self.git("rev-parse", head + ":one")
        # This is a synthetic fixture object, never the product repository.
        blob = self.repo / ".git" / "objects" / oid[:2] / oid[2:]
        blob.chmod(0o600)
        blob.unlink()
        with self.assertRaises(GateError):
            GitRepo(self.repo).range(self.base, head)

    def test_unrelated_graph_rejects(self):
        self.git("checkout", "-q", "--orphan", "unrelated")
        head = self.commit("unrelated", "unrelated")
        with self.assertRaises(GateError):
            GitRepo(self.repo).range(self.base, head)

    def test_event_source_binding(self):
        head = self.commit("one", "one")
        for kwargs in [{"expected_head": self.base}, {"expected_base": head},
                       {"repository_id": 999}]:
            with self.assertRaises(GateError):
                validate_event(self.event(head), **kwargs)
        event = self.event(head)
        del event["pull_request"]["base"]
        with self.assertRaises(GateError):
            validate_event(event)

    def test_duplicate_json_and_incomplete_api_list_reject(self):
        with self.assertRaises(GateError):
            parse_json(b'{"title":"one","title":"two"}')
        with self.assertRaises(GateError):
            validate_event({"commits": []})

    def test_hidden_footer_placeholder_and_ai_ads(self):
        for extra in ["[no ci]", "[skip actions]", "skip-checks:true", "\u202e",
                      "Generated with [Claude Code](https://example.org)",
                      "Co-authored-by: Claude Sonnet 4 <bot@example.org>"]:
            with self.assertRaises(GateError):
                validate_message(GOOD + "\n" + extra)
        for body in ["<!-- Explain the reason here -->", "Signed-off-by: Human <h@example.org>\n"
                     "  This is only a continuation of the footer.", "YOUR RATIONALE"]:
            with self.assertRaises(GateError):
                validate_message(GOOD.split("\n\n")[0] + "\n\n" + body)
        with self.assertRaises(GateError):
            validate_message(GOOD + "\n Co-authored-by: Claude Code <bot@example.org>\n")
        with self.assertRaises(GateError):
            validate_message("fix(core): Explain a change\n\n- [x] Check meaningful words only")
        validate_identity({"name": "Real Engineer", "email": "engineer@openai.com"})
        validate_message(GOOD + "\nDiscuss Claude as a supported provider, not as a co-author.\n")

    def test_merge_message_and_identity_changes(self):
        head = self.commit("one", "one")
        identity = {"author": {"name": "Human A", "email": "a@example.org"},
                    "committer": {"name": "Human B", "email": "b@example.org"}}
        first = validate_event(self.event(head), merge_message=GOOD, merge_metadata=identity)
        identity["committer"]["name"] = "Human C"
        second = validate_event(self.event(head), merge_message=GOOD, merge_metadata=identity)
        self.assertNotEqual(first["metadata_sha256"], second["metadata_sha256"])
        with self.assertRaises(GateError):
            validate_event(self.event(head), merge_message="Merge default")

    def test_local_hook_refuses_replacement_and_custom_path(self):
        hook = self.repo / ".git" / "hooks" / "commit-msg"
        hook.write_text("existing hook")
        with self.assertRaises(GateError):
            install(self.repo)
        self.assertEqual(hook.read_text(), "existing hook")
        hook.unlink()
        self.git("config", "core.hooksPath", "custom")
        with self.assertRaises(GateError):
            install(self.repo)
        self.assertFalse(hook.exists())

    def test_local_hook_install_does_not_set_configuration(self):
        original = (self.repo / ".git" / "config").read_bytes()
        install(self.repo)
        self.assertEqual((self.repo / ".git" / "config").read_bytes(), original)
        self.assertIn('--message-file "$1"', (self.repo / ".git" / "hooks" / "commit-msg").read_text())

    def test_installed_hook_enforces_message(self):
        install(self.repo)
        (self.repo / "new-file").write_text("synthetic")
        self.git("add", "new-file")
        proc = subprocess.run(["git", "-C", str(self.repo), "commit", "-m", "bad message"], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
        self.git("commit", "-q", "-m", GOOD)

    def test_cli_errors_never_echo_arguments_or_messages(self):
        marker = "sensitive-" + os.urandom(16).hex()
        message = self.repo / "message.txt"
        message.write_text(marker)
        for name, args in [("check_commit.py", ["--message-file", str(message)]),
                           ("check_pr.py", ["--unknown", marker]),
                           ("scan_credentials.py", ["--repo", marker])]:
            proc = subprocess.run([sys.executable, str(ROOT / name), *args], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn(marker.encode(), proc.stdout + proc.stderr)
            self.assertNotIn(b"Traceback", proc.stdout + proc.stderr)
