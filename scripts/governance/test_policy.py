"""Synthetic contract tests; no checked-in credential-shaped values."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from policy import validate_message, validate_identity
from common import GateError, GitRepo
from check_pr import validate_event

GOOD = "fix(core): Keep useful history\n\nPreserve each change so reviewers can trace its reason.\n"


class MessageTests(unittest.TestCase):
    def test_valid_crlf_and_unicode(self):
        validate_message(GOOD.replace("\n", "\r\n"))
        validate_message(GOOD.replace("useful", "Ünicode"))

    def test_invalid_messages(self):
        for text in ["fix: Missing scope\n\nThis change preserves useful evidence.",
                     GOOD.replace("fix(", "revert("), GOOD.replace(": ", ":  "),
                     GOOD.replace("history\n", "history.\n"),
                     "fix(core): Keep useful history\n\nCo-authored-by: A <a@example.org>",
                     "fix(core): Keep useful history\n\nTODO", GOOD + "[skip ci]\n",
                     GOOD + "[ci skip]\n", GOOD + "skip-checks: true\n",
                     GOOD + "[s\u200bkip ci]\n", GOOD + "\x1b[31m",
                     "fixup! " + GOOD, "Merge branch x\n\nPreserve useful history.",
                     GOOD.replace("\n\n", "\n"), GOOD + "x" * 73]:
            with self.subTest(case=text[:10]), self.assertRaises(GateError):
                validate_message(text)

    def test_short_rationale_has_no_word_or_letter_minimum(self):
        header = "fix(core): Preserve compatibility"
        for reason in ("Avoid deadlocks", "Preserve compatibility", "Fix a race", "Repair"):
            with self.subTest(reason=reason):
                validate_message(header + "\n\n" + reason)
        validate_message("fix(core): Preserve Café identifiers\n\nAvoid deadlocks")
        validate_identity({"name": "李明 Renée", "email": "real@example.org"})
        # Syntax does not certify English or semantic sufficiency.
        validate_message(header + "\n\n避免死锁")

    def test_markup_only_is_not_rationale(self):
        header = "fix(core): Preserve compatibility\n\n"
        for body in ("", "---", "123", "<br>", "<span></span>",
                     "`identifier`", "![diagram](https://example.org)",
                     "```python\nprint('synthetic')\n```", "<!-- hidden explanation"):
            with self.subTest(body=body), self.assertRaises(GateError):
                validate_message(header + body)
        validate_message(header + "<span>Avoid deadlocks</span>")

    def test_placeholder_words_in_engineering_prose_are_allowed(self):
        validate_message("docs(repo): explain TODO handling\n\n"
                         "Avoid publishing TODO markers in generated documentation.")
        for marker in ("TODO", "TBD", "FIXME"):
            validate_message(f"docs(repo): Explain {marker} handling\n\n"
                             f"Keep {marker} examples visible to contributors.")
        validate_message("docs(repo): Explain marker examples\n\n"
                         "Keep examples visible.\n\n```text\nTODO\n```")
        validate_message("docs(repo): Explain marker examples\n\n"
                         "Keep examples visible.\n\n    TODO")

    def test_standalone_and_seed_placeholders_reject(self):
        for placeholder in ("TODO", "TBD", "FIXME", "TBA", "YOUR RATIONALE",
                            "<summary>", "<reason>", "<Describe why this is needed.>",
                            "Replace this"):
            with self.subTest(placeholder=placeholder), self.assertRaises(GateError):
                validate_message(GOOD + "\n" + placeholder)
        for subject in ("TODO", "TBD", "<summary>"):
            with self.assertRaises(GateError):
                validate_message("docs(repo): " + subject + "\n\nAvoid broken links.")

    def test_checkbox_and_indented_code_continuations_are_not_prose(self):
        for body in ("- [ ] Reviewed\n  every changed file",
                     "* [x] Checked\ncontinuation without a blank line",
                     "+ [ ] Reviewed all changes", "1. [ ] Reviewed all changes",
                     "    print('only code')", "- [ ] Reviewed\n\n  continuation"):
            with self.subTest(kind=body.splitlines()[0][:6]), self.assertRaises(GateError):
                validate_message("fix(core): Keep history\n\n" + body)
        validate_message("fix(core): Keep history\n\n- [x] Checked\n\nAvoid deadlocks")

    def test_empty_trailers_and_lazy_quote_are_not_rationale(self):
        for body in ("Refs:\n  issue-42", "Signed-off-by:\n  Real Human",
                     "> Review evidence\nwithout ordinary prose"):
            with self.assertRaises(GateError):
                validate_message("fix(core): Keep history\n\n" + body)

    def test_width_boundaries(self):
        prefix = "fix(core): "
        body = "\n\n" + "Reason for " + "x" * 61
        validate_message(prefix + "x" * (50 - len(prefix)) + body)
        for text in [prefix + "x" * (51 - len(prefix)) + body, GOOD + "x" * 73]:
            with self.assertRaises(GateError):
                validate_message(text)

    def test_genuine_identities(self):
        for name, email in [("Renée Zhang", "123+user@users.noreply.github.com"),
                            ("dependabot[bot]", "bot@users.noreply.github.com"),
                            ("External Author", "person@example.org"),
                            ("Claude", "claude@example.org"),
                            ("Claude", "123+claude@users.noreply.github.com"),
                            ("copilot[bot]", "copilot@github.com"),
                            ("Real Engineer", "engineer@anthropic.com")]:
            validate_identity({"name": name, "email": email})
        validate_message(GOOD + "\nCo-authored-by: Real Human <real@example.org>\n")
        validate_message(GOOD + "\nCo-authored-by: Claude <claude@example.org>\n")

    def test_unambiguous_generated_ai_coauthors_reject(self):
        for name, email in [("Claude Code", "bot@example.org"),
                            ("Claude Sonnet 4", "bot@example.org"),
                            ("OpenAI Codex", "bot@example.org"),
                            ("ChatGPT", "bot@example.org"),
                            ("GitHub Copilot", "bot@example.org"),
                            ("Claude", "noreply@anthropic.com")]:
            with self.subTest(name=name), self.assertRaises(GateError):
                validate_message(GOOD + f"\nCo-authored-by: {name} <{email}>\n")


class GitFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Human")
        self.git("config", "user.email", "human@example.org")
        self.base = self.commit("base.txt", "base\n")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True).stdout.decode().strip()

    def commit(self, name, text, message=GOOD):
        (self.repo / name).write_text(text, encoding="utf-8")
        self.git("add", "--", name)
        self.git("-c", "core.hooksPath=", "commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def event(self, head):
        return {"action": "opened", "number": 7, "repository": {"id": 123},
                "pull_request": {"number": 7, "title": GOOD.splitlines()[0],
                                 "body": GOOD.split("\n\n", 1)[1],
                                 "base": {"sha": self.base, "repo": {"id": 123}},
                                 "head": {"sha": head}}}


class GraphTests(GitFixture):
    def test_full_range_and_diverged_current_base(self):
        head = self.commit("one", "one")
        self.git("checkout", "-q", "-b", "base-advance", self.base)
        advanced = self.commit("other", "other")
        graph = GitRepo(self.repo).range(advanced, head)
        self.assertEqual([c.oid for c in graph], [head])

    def test_missing_and_injection_and_shallow(self):
        head = self.commit("one", "one")
        for base in ["0" * 40, "HEAD", self.base + ";echo unsafe"]:
            with self.assertRaises(GateError):
                GitRepo(self.repo).range(base, head)
        (self.repo / ".git" / "shallow").write_text(self.base + "\n")
        with self.assertRaises(GateError):
            GitRepo(self.repo).range(self.base, head)

    def test_good_title_cannot_hide_bad_commit(self):
        self.commit("bad", "bad", "bad old message")
        head = self.commit("good", "good")
        with self.assertRaises(GateError):
            validate_event(self.event(head), repo=GitRepo(self.repo))

    def test_pr_discussion_and_untouched_template(self):
        event = self.event(self.base)
        event["pull_request"]["title"] = "docs(repo): explain TODO handling"
        event["pull_request"]["body"] = "Avoid publishing TODO markers in generated documentation."
        validate_event(event)
        template = Path(__file__).resolve().parents[2] / ".github" / "pull_request_template.md"
        event["pull_request"]["body"] = template.read_text(encoding="utf-8")
        with self.assertRaisesRegex(GateError, "template-placeholder"):
            validate_event(event)

    def test_edited_metadata_changes_evidence(self):
        head = self.commit("one", "one")
        event = self.event(head)
        short = self.event(head)
        short["pull_request"]["body"] = "Avoid deadlocks"
        validate_event(short, repo=GitRepo(self.repo))
        before = validate_event(event, repo=GitRepo(self.repo))
        event["action"] = "edited"
        event["pull_request"]["body"] += "\nExplain why another detail needs review."
        after = validate_event(event, repo=GitRepo(self.repo))
        self.assertNotEqual(before["metadata_sha256"], after["metadata_sha256"])
        event["pull_request"]["title"] = "Invalid title"
        with self.assertRaises(GateError):
            validate_event(event, repo=GitRepo(self.repo))


if __name__ == "__main__":
    unittest.main()
