"""Execute workflow control blocks on synthetic inputs; no YAML dependency."""
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

from common import GateError
from test_policy import GitFixture

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/governance.yml"
CHECKOUT = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
PYTHON = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"


def job(name):
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", text)
    if match is None:
        raise AssertionError("missing required job")
    return match[1]


def step(job_name, ident):
    for part in re.split(r"(?m)^      - ", job(job_name)):
        if re.search(r"(?m)^        id: " + re.escape(ident) + r"$", part):
            return part
    raise AssertionError("missing required step")


def load_step(job_name, ident):
    block = step(job_name, ident)
    match = re.search(r"(?ms)^        run: \|\n(.*)$", block)
    if match is None or "shell: python {0}" not in block:
        raise AssertionError("workflow control must be explicit Python")
    source = "\n".join(line[10:] for line in match[1].splitlines())
    scope = {"__name__": "workflow_contract"}
    exec(compile(source, "<workflow-control>", "exec"), scope)
    return scope, source


def oid(label):
    return hashlib.sha1(label.encode()).hexdigest()


class EventContractTests(unittest.TestCase):
    def setUp(self):
        self.control, _ = load_step("prepare", "resolve")
        self.event = {"action": "opened", "number": 7,
                      "repository": {"id": 123, "full_name": "sample/project"},
                      "pull_request": {"number": 7,
                          "base": {"sha": oid("base"), "ref": "main", "repo": {"id": 123}},
                          "head": {"sha": oid("head")}, "title": "synthetic", "body": "synthetic"}}

    def resolve(self, event=None, kind="pull_request"):
        return self.control["resolve_event"](self.event if event is None else event,
                                             kind, "sample/project", "123")

    def test_all_pr_events_and_push_use_exact_nonzero_range(self):
        for action in ("opened", "synchronize", "reopened", "edited"):
            self.event["action"] = action
            result = self.resolve()
            self.assertEqual(result["base"], oid("base"))
            self.assertEqual(result["head"], oid("head"))
        push = {"repository": self.event["repository"], "ref": "refs/heads/main",
                "before": oid("before"), "after": oid("after"), "deleted": False}
        self.assertEqual(self.resolve(push, "push")["base"], oid("before"))
        for field in ("before", "after"):
            changed = copy.deepcopy(push)
            changed[field] = "0" * 40
            with self.assertRaises(ValueError):
                self.resolve(changed, "push")
        push["deleted"] = True
        with self.assertRaises(ValueError):
            self.resolve(push, "push")

    def test_bad_refs_missing_fields_wrong_repository_and_event_fail(self):
        for value in (None, "", "main", "HEAD", "0" * 40, "A" * 40,
                      oid("base") + "\n", "--upload-pack=unexpected", "$(echo injected)"):
            changed = copy.deepcopy(self.event)
            changed["pull_request"]["head"]["sha"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.resolve(changed)
        changes = (("repository", {"id": True, "full_name": "sample/project"}),
                   ("repository", {"id": 124, "full_name": "sample/project"}),
                   ("repository", {"id": 123, "full_name": "other/project"}),
                   ("number", 8), ("action", "closed"), ("pull_request", {}))
        for key, value in changes:
            changed = copy.deepcopy(self.event)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.resolve(changed)
        with self.assertRaises(ValueError):
            self.resolve(kind="workflow_dispatch")

    def test_metadata_never_becomes_output_or_shell_source(self):
        sentinel = "$(echo untrusted)\nhead=injected\n::notice::not-an-output"
        self.event["pull_request"]["title"] = sentinel
        self.event["pull_request"]["body"] = sentinel
        result = self.resolve()
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertEqual(set(result), {"base", "head", "repository_id", "event"})

    def test_malformed_json_main_fails_without_echo(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text("sensitive-invalid-json", encoding="utf-8")
            output = Path(directory) / "output"
            _, source = load_step("prepare", "resolve")
            logs = io.StringIO()
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event),
                                         "GITHUB_OUTPUT": str(output)}):
                with contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs):
                    with self.assertRaises(SystemExit) as exit_result:
                        exec(compile(source, "<synthetic-event>", "exec"), {"__name__": "__main__"})
            self.assertEqual(exit_result.exception.code, 1)
            self.assertNotIn("sensitive-invalid-json", logs.getvalue())
            self.assertIn("event rejected", logs.getvalue())
            self.assertFalse(output.exists())


class FreshPullRequestTests(unittest.TestCase):
    def setUp(self):
        self.control, self.source = load_step("metadata", "fresh-pr")
        self.trigger = {"action": "edited", "number": 7,
                        "repository": {"id": 123, "full_name": "sample/project"},
                        "pull_request": {"number": 7, "title": "fix(core): Preserve compatibility",
                            "body": "Avoid deadlocks", "state": "open",
                            "base": {"ref": "main", "sha": oid("base"),
                                     "repo": {"id": 123, "full_name": "sample/project"}},
                            "head": {"sha": oid("head")}}}
        self.current = copy.deepcopy(self.trigger["pull_request"])

    def bind(self, current=None, base=None, head=None):
        return self.control["bind_current_event"](self.trigger,
                    self.current if current is None else current,
                    oid("base") if base is None else base, oid("head") if head is None else head,
                    "sample/project", "123")

    def test_current_api_values_feed_the_metadata_digest(self):
        from check_pr import validate_event
        fresh = self.bind()
        self.assertIs(fresh["pull_request"], self.current)
        self.assertEqual(validate_event(fresh)["metadata_sha256"],
                         validate_event(self.trigger)["metadata_sha256"])
        self.current["body"] = "Preserve compatibility"
        with self.assertRaises(ValueError):
            self.bind()
        updated = copy.deepcopy(self.trigger)
        updated["pull_request"] = self.current
        self.assertNotEqual(validate_event(updated)["metadata_sha256"],
                            validate_event(self.trigger)["metadata_sha256"])

    def test_stale_title_body_head_and_base_are_rejected(self):
        for field in ("title", "body", "head", "base"):
            current = copy.deepcopy(self.current)
            if field in ("head", "base"):
                current[field]["sha"] = oid("new-" + field)
            else:
                current[field] += " changed"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.bind(current)
        for kwargs in ({"base": oid("different")}, {"head": oid("different")}):
            with self.assertRaises(ValueError):
                self.bind(**kwargs)

    def test_closed_wrong_target_and_invalid_api_paths_are_rejected(self):
        for field, value in (("state", "closed"), ("number", 8)):
            current = copy.deepcopy(self.current)
            current[field] = value
            with self.assertRaises((ValueError, GateError)):
                self.bind(current)
        current = copy.deepcopy(self.current)
        current["base"]["ref"] = "other"
        with self.assertRaises(ValueError):
            self.bind(current)
        self.assertEqual(self.control["api_url"]("sample/project", 7),
                         "https://api.github.com/repos/sample/project/pulls/7")
        for repository in ("sample/project?token=bad", "sample/project/other", "sample/..", "sample/.", "sample%2fproject", "$(echo bad)", None):
            with self.assertRaises(ValueError):
                self.control["api_url"](repository, 7)
        for number in (True, 0, -1, "7", "7;echo bad"):
            with self.assertRaises(ValueError):
                self.control["api_url"]("sample/project", number)

    def test_api_raw_json_is_private_and_only_safe_fields_are_outputs(self):
        import tempfile
        payload = json.dumps(self.current).encode()
        token = "synthetic-" + oid("read-only-token")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = root / "event.json"
            event.write_text(json.dumps(self.trigger), encoding="utf-8")
            source = root / "control.py"
            source.write_text(self.source, encoding="utf-8")
            output = root / "outputs"
            env = {"GITHUB_EVENT_PATH": str(event), "GITHUB_REPOSITORY": "sample/project",
                   "REPOSITORY_ID": "123", "BASE_SHA": oid("base"), "HEAD_SHA": oid("head"),
                   "GH_TOKEN": token, "RUNNER_TEMP": directory, "GITHUB_OUTPUT": str(output), "PR_EVIDENCE_PHASE": "capture"}
            with patch.dict(os.environ, env), patch.object(sys, "path", sys.path[:]):
                with patch("urllib.request.build_opener") as opener:
                    opener.return_value.open.return_value = contextlib.nullcontext(io.BytesIO(payload))
                    with patch.dict(self.control, {"__file__": str(source)}), contextlib.redirect_stdout(io.StringIO()) as logs:
                        self.control["main"]()
                    request = opener.return_value.open.call_args.args[0]
                    self.assertEqual(request.full_url, self.control["api_url"]("sample/project", 7))
                    self.assertEqual(request.get_header("Authorization"), "Bearer " + token)
            self.assertNotIn(self.current["body"], output.read_text(encoding="utf-8"))
            self.assertNotIn(token, logs.getvalue())
            self.assertEqual((root / "governance-current-pr-api.json").read_bytes(), payload)
            fresh = json.loads((root / "governance-current-pr-event.json").read_bytes())
            self.assertEqual(fresh["pull_request"], self.current)


    def test_final_recheck_preserves_complete_validated_event(self):
        import tempfile
        from common import digest
        from check_pr import validate_event
        changes = ({"user": {"login": "changed-human"}}, {"mergeable": True},
                   {"comments": 1}, {"updated_at": "synthetic-later"},
                   {"labels": [{"name": "/" + "home/" + oid("synthetic-label-reader")}]},
                   {"new_metadata": {"private": "/" + "home/" + oid("synthetic-reader")}})
        for change in ({}, *changes):
            with self.subTest(change=tuple(change)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                event = root / "event.json"
                event.write_text(json.dumps(self.trigger), encoding="utf-8")
                source = root / "control.py"
                source.write_text(self.source, encoding="utf-8")
                output = root / "outputs"
                env = {"GITHUB_EVENT_PATH": str(event), "GITHUB_REPOSITORY": "sample/project",
                       "REPOSITORY_ID": "123", "BASE_SHA": oid("base"), "HEAD_SHA": oid("head"),
                       "GH_TOKEN": "synthetic-" + oid("api-token"), "RUNNER_TEMP": directory,
                       "GITHUB_OUTPUT": str(output), "PR_EVIDENCE_PHASE": "capture"}
                with patch.dict(os.environ, env), patch.object(sys, "path", sys.path[:]):
                    with patch("urllib.request.build_opener") as opener, patch.dict(self.control, {"__file__": str(source)}):
                        opener.return_value.open.return_value = contextlib.nullcontext(io.BytesIO(json.dumps(self.current).encode()))
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.control["main"]()
                        frozen = root / "governance-current-pr-event.json"
                        before = frozen.read_bytes()
                        original = json.loads(before)
                        before_outputs = output.read_bytes()
                        original_metadata = validate_event(original)["metadata_sha256"]
                        final_current = {**self.current, **change}
                        final_event = {**self.trigger, "pull_request": final_current}
                        if change:
                            self.assertNotEqual(validate_event(final_event)["metadata_sha256"], original_metadata)
                        opener.return_value.open.return_value = contextlib.nullcontext(io.BytesIO(json.dumps(final_current).encode()))
                        with patch.dict(os.environ, {"PR_EVIDENCE_PHASE": "recheck", "VALIDATED_EVENT_SHA256": digest(original)}):
                            with contextlib.redirect_stdout(io.StringIO()):
                                if change:
                                    with self.assertRaises(ValueError):
                                        self.control["main"]()
                                else:
                                    self.control["main"]()
                        self.assertEqual(frozen.read_bytes(), before)
                        self.assertEqual(output.read_bytes(), before_outputs)
                        self.assertEqual(validate_event(json.loads(frozen.read_bytes()))["metadata_sha256"], original_metadata)


    def test_api_failure_never_logs_raw_response_or_token(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps(self.trigger), encoding="utf-8")
            token = "synthetic-" + oid("private-token")
            env = {"GITHUB_EVENT_PATH": str(event), "GITHUB_REPOSITORY": "sample/project",
                   "REPOSITORY_ID": "123", "BASE_SHA": oid("base"), "HEAD_SHA": oid("head"),
                   "GH_TOKEN": token, "RUNNER_TEMP": directory, "PR_EVIDENCE_PHASE": "capture"}
            logs = io.StringIO()
            with patch.dict(os.environ, env), patch.object(sys, "path", sys.path[:]):
                with patch("urllib.request.build_opener") as opener:
                    opener.return_value.open.side_effect = OSError("private-api-response " + token)
                    with contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs):
                        with self.assertRaises(SystemExit) as result:
                            exec(compile(self.source, "<api-control>", "exec"), {"__name__": "__main__"})
            self.assertEqual(result.exception.code, 1)
            self.assertNotIn("private-api-response", logs.getvalue())
            self.assertNotIn(token, logs.getvalue())


class TrustContractTests(GitFixture):
    def setUp(self):
        super().setUp()
        self.control, self.source = load_step("metadata", "select-trusted")

    def install(self, omit=None):
        for name in self.control["REQUIRED"]:
            if name != omit:
                path = self.repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic trusted fixture\n", encoding="utf-8")
        self.git("add", "--", "scripts")
        self.git("-c", "core.hooksPath=", "commit", "-q", "-m", "Synthetic fixture")
        return self.git("rev-parse", "HEAD")

    def test_absence_requires_explicit_immutable_bootstrap(self):
        for value in ("", "main", "HEAD", "0" * 40, oid("frozen") + "\n", "${candidate}"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.control["choose_source"](self.repo, self.base, value)
        self.assertEqual(self.control["choose_source"](self.repo, self.base, oid("frozen")),
                         (oid("frozen"), "bootstrap"))
        self.assertNotIn("GITHUB_SHA", self.source)
        self.assertNotIn("HEAD_SHA", self.source)

    def test_complete_base_wins_over_any_bootstrap_setting(self):
        current = self.install()
        for value in ("", "invalid", oid("alternate")):
            self.assertEqual(self.control["choose_source"](self.repo, current, value),
                             (current, "base"))

    def test_partial_base_never_falls_back(self):
        for omitted in self.control["REQUIRED"]:
            with self.subTest(omitted=omitted):
                self.git("checkout", "-q", self.base)
                current = self.install(omitted)
                with self.assertRaises(ValueError):
                    self.control["choose_source"](self.repo, current, oid("frozen"))

    def test_non_directory_tooling_and_wrong_checkout_fail(self):
        (self.repo / "scripts").mkdir()
        current = self.commit("scripts/governance", "not a directory")
        with self.assertRaises(ValueError):
            self.control["choose_source"](self.repo, current, oid("frozen"))
        with self.assertRaises(ValueError):
            self.control["verify_checkout"](self.repo, self.base)

    def test_selected_revision_must_contain_complete_regular_tools(self):
        current = self.install()
        self.control["verify_checkout"](self.repo, current)
        with self.assertRaises(ValueError):
            self.control["verify_checkout"](self.repo, oid("unavailable"))
        name = "scripts/governance/policy.py"
        blob = self.git("rev-parse", "HEAD:" + name)
        self.git("update-index", "--cacheinfo", "120000," + blob + "," + name)
        self.git("-c", "core.hooksPath=", "commit", "-q", "-m", "Synthetic link fixture")
        current = self.git("rev-parse", "HEAD")
        with self.assertRaises(ValueError):
            self.control["verify_checkout"](self.repo, current)


    def test_shallow_checkout_is_not_trusted(self):
        current = self.install()
        clone = Path(self.temp.name) / "shallow"
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", self.repo.as_uri(), str(clone)],
                       capture_output=True, check=True)
        with self.assertRaises(ValueError):
            self.control["choose_source"](clone, current, oid("frozen"))


class PrivacyWorkflowTests(GitFixture):
    def setUp(self):
        super().setUp()
        self.control, _ = load_step("metadata", "validate")
        self.paths = patch.object(sys, "path", [str(ROOT / "scripts/evidence"), *sys.path])
        self.paths.start()
        self.addCleanup(self.paths.stop)

    def scan(self, head, event=None):
        event_file = Path(self.temp.name) / "event.json"
        if event is not None:
            event_file.write_text(json.dumps(event), encoding="utf-8")
        commands = self.control["commands"](sys.executable, ROOT, self.repo, self.base, head,
                                            "123", str(event_file), "pull_request" if event else "push",
                                            Path(self.temp.name) / "unused-archive")
        path_commands = [command for command in commands if Path(command[1]).name == "scan_paths.py"]
        self.assertEqual(len(path_commands), 1)
        self.assertNotIn("--gitleaks-archive", path_commands[0])
        result = subprocess.run(path_commands[0], capture_output=True, check=False)
        if result.returncode:
            self.assertEqual(json.loads(result.stderr)["code"], "path-privacy-findings")
        else:
            output = json.loads(result.stdout)
            self.assertEqual(output["status"], "passed")
            self.assertEqual(output["profile"], "public")
            self.assertEqual(output["findings"], 0)
            self.assertFalse(output["all_refs_scanned"])
            self.assertFalse(output["published_assets_scanned"])
            self.assertEqual(output["history_selection"], "head-minus-base")
        return result.returncode

    def test_added_then_deleted_path_and_commit_metadata_are_checked(self):
        self.assertEqual(self.scan(self.base), 0)
        private_path = "/" + "home/" + oid("synthetic-account") + "/fixture"
        self.commit("intermediate.txt", private_path)
        self.git("rm", "--", "intermediate.txt")
        self.git("-c", "core.hooksPath=", "commit", "-q", "-m", "Synthetic removal")
        head = self.git("rev-parse", "HEAD")
        self.assertGreater(self.scan(head), 0)
        self.git("checkout", "-q", self.base)
        head = self.commit("clean.txt", "clean", "fix(core): Keep fixture private\n\n" + private_path)
        self.assertGreater(self.scan(head), 0)

    def test_event_metadata_is_a_separate_surface(self):
        head = self.commit("clean.txt", "synthetic clean text")
        event = self.event(head)
        self.assertEqual(self.scan(head, event), 0)
        event["pull_request"]["body"] = "/" + "home/" + oid("synthetic-reader")
        self.assertGreater(self.scan(head, event), 0)


    def test_private_label_changes_digest_and_fails_final_path_gate(self):
        from common import digest
        from check_pr import validate_event
        head = self.commit("clean.txt", "synthetic clean text")
        event = self.event(head)
        self.assertEqual(self.scan(head, event), 0)
        changed = copy.deepcopy(event)
        changed["pull_request"]["labels"] = [{"name": "/" + "home/" + oid("synthetic-label-owner")}]
        self.assertNotEqual(validate_event(changed)["metadata_sha256"], validate_event(event)["metadata_sha256"])
        self.assertGreater(self.scan(head, changed), 0)
        api, _ = load_step("metadata", "fresh-pr")
        frozen = Path(self.temp.name) / "validated-event.json"
        api["preserve_event"](event, frozen, "capture", None)
        before = frozen.read_bytes()
        with self.assertRaisesRegex(ValueError, "full-pr-event-changed"):
            api["preserve_event"](changed, frozen, "recheck", digest(event))
        self.assertEqual(frozen.read_bytes(), before)


    def test_snapshot_policy_is_not_rescanned_as_pathless_metadata(self):
        from privacy_scan import HISTORICAL_SNAPSHOTS
        for name in HISTORICAL_SNAPSHOTS:
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
            self.git("add", "--", name)
        self.git("-c", "core.hooksPath=", "commit", "-q", "-m", "Synthetic pinned snapshots")
        self.assertEqual(self.scan(self.git("rev-parse", "HEAD")), 0)


class WorkflowStructureTests(unittest.TestCase):
    def test_triggers_permissions_pins_and_no_leaking_surfaces(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("types: [opened, synchronize, reopened, edited]", text)
        self.assertEqual(text.count("branches: [main]"), 2)
        self.assertIn("permissions:\n  contents: read\n", text)
        refs = re.findall(r"uses: (\S+)", text)
        self.assertTrue(refs)
        self.assertTrue(all(ref in (CHECKOUT, PYTHON) for ref in refs))
        for forbidden in ("pull_request_target", "workflow_run:", "secrets.",
                          "contents: write", "continue-on-error", "upload-artifact",
                          "actions/cache", "cargo ", "paths-ignore:", "paths:"):
            self.assertNotIn(forbidden, text)
        checkouts = re.findall(r"(?ms)^      - uses: " + re.escape(CHECKOUT) + r"\n(.*?)(?=^      - |\Z)", text)
        self.assertEqual(len(checkouts), 4)
        for checkout in checkouts:
            self.assertIn("persist-credentials: false", checkout)
            self.assertIn("fetch-depth: 0", checkout)
            self.assertIn("ref: ${{", checkout)
        for name in ("prepare", "metadata", "checker-tests", "gate"):
            self.assertIn("timeout-minutes:", job(name))

    def test_no_expression_interpolation_inside_run_blocks(self):
        for name, ident in (("prepare", "resolve"), ("metadata", "select-trusted"),
                            ("metadata", "verify-trusted"), ("metadata", "fresh-pr"),
                            ("metadata", "validate"), ("metadata", "recheck-pr"),
                            ("checker-tests", "fixture"), ("checker-tests", "self-tests"),
                            ("gate", "aggregate")):
            _, source = load_step(name, ident)
            self.assertNotIn("${{", source)
            self.assertNotIn("shell=True", source)

    def test_trust_separation_and_archive_required_for_tests(self):
        trusted = job("metadata")
        candidate = job("checker-tests")
        self.assertIn("GOVERNANCE_BOOTSTRAP_SHA: ${{ vars.GOVERNANCE_BOOTSTRAP_SHA }}", trusted)
        self.assertIn("ref: ${{ steps.select-trusted.outputs.source }}", trusted)
        self.assertNotIn("unittest", trusted)
        self.assertNotIn("bootstrap", candidate.lower())
        self.assertNotIn("provision_gitleaks.py", candidate)
        self.assertIn("GOVERNANCE_TEST_ARCHIVE", candidate)
        self.assertIn("test_*.py", candidate)
        self.assertIn('"check_commit.py"', trusted)
        self.assertIn('"check_pr.py"', trusted)
        self.assertIn('"scan_credentials.py"', trusted)
        self.assertIn('"scan_paths.py"', trusted)
        self.assertNotIn("def privacy_findings", trusted)
        self.assertNotIn("collect_surfaces", trusted)
        self.assertNotIn("scan_content", trusted)
        self.assertIn("refs/remotes/origin/main", trusted)


    def test_api_token_is_scoped_to_trusted_read_steps(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(text.count("pull-requests: read"), 1)
        self.assertIn("pull-requests: read", job("metadata"))
        self.assertNotIn("GH_TOKEN", job("checker-tests"))
        self.assertNotIn("GH_TOKEN", step("metadata", "validate"))
        self.assertEqual(text.count("GH_TOKEN: ${{ github.token }}"), 2)
        for ident in ("fresh-pr", "recheck-pr"):
            self.assertIn("GH_TOKEN: ${{ github.token }}", step("metadata", ident))
            self.assertIn("if: github.event_name == 'pull_request'", step("metadata", ident))
        validation = step("metadata", "validate")
        self.assertIn("FRESH_BASE_SHA: ${{ steps.fresh-pr.outputs.base }}", validation)
        self.assertIn("FRESH_HEAD_SHA: ${{ steps.fresh-pr.outputs.head }}", validation)
        self.assertIn("FRESH_EVENT_FILE: ${{ steps.fresh-pr.outputs.event_file }}", validation)
        self.assertIn('event_file = os.environ["FRESH_EVENT_FILE"]', validation)
        self.assertIn("FRESH_EVENT_SHA256: ${{ steps.fresh-pr.outputs.event_sha256 }}", validation)
        self.assertIn("PR_EVIDENCE_PHASE: capture", step("metadata", "fresh-pr"))
        self.assertIn("PR_EVIDENCE_PHASE: recheck", step("metadata", "recheck-pr"))
        self.assertIn("VALIDATED_EVENT_SHA256: ${{ steps.validate.outputs.event_sha256 }}", step("metadata", "recheck-pr"))
        self.assertEqual(validation.count("digest(parse_json(read_bytes(event_file))) != event_hash"), 2)
        self.assertLess(job("metadata").index("id: validate"), job("metadata").index("id: recheck-pr"))


    def test_helper_argv_bind_repo_sha_identity_and_event(self):
        control, _ = load_step("metadata", "validate")
        commands = control["commands"]("python", Path("trusted"), Path("candidate"),
                                        oid("base"), oid("head"), "123", "event;injection", "pull_request", Path("archive"))
        self.assertEqual(len(commands), 4)
        for command in commands:
            self.assertIn("--repo", command)
            self.assertIn(oid("head"), command)
            self.assertIn(oid("base"), command)
        self.assertIn("--repository-id", commands[1])
        self.assertIn("--expected-base", commands[1])
        self.assertIn("event;injection", commands[1])
        self.assertEqual(Path(commands[2][1]).name, "scan_paths.py")
        self.assertEqual(Path(commands[3][1]).name, "scan_credentials.py")
        for command in commands[2:]:
            self.assertIn("--event-file", command)
            self.assertIn("event;injection", command)
            self.assertIn("--repository-id", command)
        self.assertNotIn("--gitleaks-archive", commands[2])
        self.assertNotIn("--platform", commands[2])
        self.assertIn("--gitleaks-archive", commands[3])
        push = control["commands"]("python", Path("trusted"), Path("candidate"),
                                    oid("base"), oid("head"), "123", "event", "push", Path("archive"))
        self.assertEqual(len(push), 3)
        self.assertEqual([Path(command[1]).name for command in push],
                         ["check_commit.py", "scan_paths.py", "scan_credentials.py"])
        self.assertNotIn("--event-file", push[-2])
        self.assertNotIn("--event-file", push[-1])


    def test_trusted_completeness_includes_path_gate_and_dependencies(self):
        control, _ = load_step("metadata", "select-trusted")
        required = set(control["REQUIRED"])
        self.assertTrue({"scripts/governance/scan_paths.py", "scripts/governance/credential_scan.py",
                         "scripts/evidence/privacy_scan.py", "scripts/release/export_public_tree.py",
                         "scripts/governance/policy.json", "scripts/governance/gitleaks.toml",
                         "scripts/governance/reviewed_sqlite.json"}.issubset(required))
        for name in required:
            if not name.endswith(".py"):
                continue
            for node in ast.walk(ast.parse((ROOT / name).read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom) and node.module:
                    module = "scripts/governance/" + node.module.split(".")[0] + ".py"
                    if (ROOT / module).is_file():
                        self.assertIn(module, required)

    def test_each_privacy_command_must_actually_succeed(self):
        control, _ = load_step("metadata", "validate")
        for failed in ("scan_paths.py", "scan_credentials.py"):
            for code, status in ((1, "rejected"), (0, "missing")):
                called = []
                def run(argv, **kwargs):
                    name = Path(argv[1]).name
                    called.append(name)
                    if name == "provision_gitleaks.py":
                        return 0, b'{"status":"provisioned"}'
                    if name == failed:
                        return code, json.dumps({"status": status}).encode()
                    return 0, b'{"status":"passed"}'
                env = {"BASE_SHA": oid("base"), "HEAD_SHA": oid("head"), "EVENT_KIND": "push",
                       "REPOSITORY_ID": "123", "GITHUB_EVENT_PATH": "unused-event", "RUNNER_TEMP": "unused-temp",
                       "TOOLING_MODE": "base"}
                with self.subTest(failed=failed, code=code), patch.dict(os.environ, env):
                    with patch.object(sys, "path", sys.path[:]), patch("common.GitRepo") as repo:
                        repo.return_value.git.return_value = (oid("head") + "\n").encode()
                        with patch("common.run", side_effect=run), contextlib.redirect_stdout(io.StringIO()) as output:
                            with self.assertRaisesRegex(ValueError, "required-helper-rejected|missing-helper-success"):
                                control["main"]()
                        self.assertIn(failed, called)
                        self.assertNotIn('"status": "passed"', output.getvalue())
                        if failed == "scan_credentials.py":
                            self.assertIn("scan_paths.py", called)


    def test_aggregate_accepts_only_both_actual_successes(self):
        control, _ = load_step("gate", "aggregate")
        self.assertIn("if: ${{ always() }}", job("gate"))
        self.assertIn("needs: [metadata, checker-tests]", job("gate"))
        good = {name: {"result": "success"} for name in ("metadata", "checker-tests")}
        self.assertTrue(control["accepted"](good))
        for name in good:
            for value in ("failure", "cancelled", "skipped", "pending", "", None):
                changed = copy.deepcopy(good)
                changed[name]["result"] = value
                self.assertFalse(control["accepted"](changed))
            changed = copy.deepcopy(good)
            del changed[name]
            self.assertFalse(control["accepted"](changed))
        for value in (None, [], {}, {"metadata": {}}, {**good, "unexpected": {}}):
            self.assertFalse(control["accepted"](value))


    def test_candidate_tests_cannot_skip_a_missing_archive(self):
        control, _ = load_step("checker-tests", "self-tests")
        for value in (None, "unavailable-synthetic-archive"):
            env = {} if value is None else {"GOVERNANCE_TEST_ARCHIVE": value}
            with patch.dict(os.environ, env, clear=True), patch("subprocess.run") as run:
                with self.assertRaises(ValueError):
                    control["main"]()
                run.assert_not_called()



    def test_candidate_runner_rejects_empty_or_failing_suites(self):
        import tempfile
        control, _ = load_step("checker-tests", "self-tests")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "scripts/governance"
            target.mkdir(parents=True)
            runner = [sys.executable, "-c", control["TEST_RUNNER"]]
            self.assertNotEqual(subprocess.run(runner, cwd=directory, capture_output=True).returncode, 0)
            test = target / "test_synthetic.py"
            for assertion, expected in (("True", 0), ("False", 1)):
                test.write_text("import unittest\nclass Synthetic(unittest.TestCase):\n"
                                "    def test_fixture(self):\n        self.assertTrue(" + assertion + ")\n", encoding="utf-8")
                result = subprocess.run(runner, cwd=directory, capture_output=True)
                self.assertEqual(result.returncode, expected)



    def test_candidate_runner_rejects_all_skipped_and_mixed_skips(self):
        import tempfile
        control, _ = load_step("checker-tests", "self-tests")
        skipped = ("    @unittest.skip('synthetic required skip')\n"
                   "    def test_skipped(self):\n        self.fail('must not run')\n")
        passing = "    def test_passed(self):\n        self.assertTrue(True)\n"
        for methods in (skipped, passing + skipped):
            with self.subTest(mixed=methods.startswith(passing)), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "scripts/governance"
                target.mkdir(parents=True)
                (target / "test_synthetic.py").write_text("import unittest\nclass Synthetic(unittest.TestCase):\n" + methods, encoding="utf-8")
                result = subprocess.run([sys.executable, "-c", control["TEST_RUNNER"]], cwd=directory, capture_output=True)
                self.assertNotEqual(result.returncode, 0)



    def test_candidate_runner_rejects_expected_failures(self):
        import tempfile
        control, _ = load_step("checker-tests", "self-tests")
        passing = "    def test_passed(self):\n        self.assertTrue(True)\n"
        for expected_failure, mixed in ((True, False), (True, True), (False, False)):
            decorated = ("    @unittest.expectedFailure\n    def test_expected(self):\n"
                         "        self.assertTrue(" + ("False" if expected_failure else "True") + ")\n")
            with self.subTest(expected_failure=expected_failure, mixed=mixed), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "scripts/governance"
                target.mkdir(parents=True)
                (target / "test_synthetic.py").write_text("import unittest\nclass Synthetic(unittest.TestCase):\n"
                                                        + (passing if mixed else "") + decorated, encoding="utf-8")
                result = subprocess.run([sys.executable, "-c", control["TEST_RUNNER"]], cwd=directory, capture_output=True)
                self.assertNotEqual(result.returncode, 0)


    def test_independent_fixture_download_hash_and_license(self):
        control, source = load_step("checker-tests", "fixture")
        from provision_gitleaks import ASSETS, VERSION, asset_name
        self.assertEqual(control["ARCHIVE"], asset_name("linux_x64"))
        self.assertEqual(control["SHA256"], ASSETS["linux_x64"][1])
        self.assertIn("/v" + VERSION + "/", control["URL"])
        self.assertNotIn("extractall", source)
        with self.assertRaises(ValueError):
            control["verified_archive"](b"bad synthetic archive")
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            payload = b"MIT synthetic fixture license\n"
            info = tarfile.TarInfo("LICENSE")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        value = data.getvalue()
        with patch.dict(control, {"SHA256": hashlib.sha256(value).hexdigest()}):
            self.assertEqual(control["verified_archive"](value), payload)


if __name__ == "__main__":
    unittest.main()
