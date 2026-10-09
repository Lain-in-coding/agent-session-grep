#!/usr/bin/env python3
"""Exercise the actual inline release controls with synthetic, offline inputs.

Like the governance tests, extract known job/step literal Python blocks rather
than approximate a YAML parser or add a dependency. Structure assertions guard
the data flow; executed controls guard rejection behavior. No hosted jobs or
real API writes are performed by this suite.
"""
from __future__ import annotations

import ast
import copy
import contextlib
import io
import gzip
import hashlib
import json
import os
import re
import subprocess
import stat
import sys
import tempfile
import tarfile
import zipfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from test_build_manifest import BUILD_MANIFEST
from test_release_workflow import has_python_gh_call

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"
WORKFLOWS = ("ci.yml", "release.yml", "release-verify.yml", "security-audit.yml")
TARGETS = ("x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu",
           "x86_64-apple-darwin", "aarch64-apple-darwin")

# Approved command inventory, deliberately independent of the candidate's own
# required_step_names() and of whichever steps remain in its YAML.
TEST_STEPS = (
    "Checkout exact source", "Assert exact source checkout", "Install Rust toolchain", "Install Python",
    "Cache cargo registry and target", "Format check", "Clippy", "Test", "Web client interaction tests",
    "Test semantic-candle feature", "Check semantic-candle entrypoints", "Robot contract tests",
    "Release verifier and entry-point tests", "Release manifest tests", "Evidence harness tests",
)
AUDIT_STEPS = (
    "Checkout exact source", "Assert exact source checkout", "Install pinned audit tools", "Verify committed lockfile",
    "Check dependency policy", "Check zero-egress static audit", "Check RustSec advisories",
)
BUILD_STEPS = (
    "Checkout exact source", "Assert exact source checkout", "Install Python", "Install Rust toolchain",
    "Download common release inputs", "Build locked release binary", "Verify exact binary version",
    "Synthetic release smoke", "Build deterministic unsigned archive and manifest",
    "Write target artifact checksums", "Upload unsigned target artifact",
)
SPECIAL_STEPS = {
    "validate exact CI source": ("Validate required source SHA",),
    "resolve audit source": ("Resolve exact audit source",),
    "all required quality checks": ("Require every quality result and matrix member",),
    "resolve exact source and release inputs": (
        "Resolve exact prepared source", "Checkout exact source", "Assert exact source checkout",
        "Install Python", "Install Rust toolchain", "Validate workspace version and immutable inputs",
        "Generate locked metadata and dependency inventory", "Upload common release inputs",
    ),
    "validate complete four-target unsigned bundle": (
        "Checkout exact source", "Assert exact source checkout", "Install Python",
        "Download separate target artifacts without merging", "Download common dependency inventory",
        "Validate target inventories before assembling", "Write complete bundle checksums with the existing helper",
        "Verify all bundle bytes and unsigned provenance", "Upload complete temporary unsigned bundle",
    ),
}

def fixture_step_names(name):
    leaf = name.split(" / ")[-1]
    if leaf.startswith("test ("):
        return TEST_STEPS
    if leaf.startswith("installer smoke ("):
        platform = "windows" if leaf == "installer smoke (windows-latest)" else "unix"
        return ("Checkout exact source", "Assert exact source checkout", "Install Rust toolchain", "Install Python",
                "Cache cargo registry and target", "Build release binary",
                f"Install into a workspace-local prefix ({platform})", f"Invoke both installed commands ({platform})",
                f"Surface smoke ({platform})", f"Uninstall twice ({platform})", "Regression harness self-test")
    if leaf == "Cargo dependency audit":
        return AUDIT_STEPS
    if leaf.startswith(("build ", "verify ")):
        return BUILD_STEPS
    return SPECIAL_STEPS.get(leaf, ())


def step_record(name, number, conclusion="success", status="completed"):
    return {"number": number, "name": name, "status": status, "conclusion": conclusion}


def read_workflow(name):
    return (WORKFLOW_DIR / name).read_text(encoding="utf-8")


def top_block(text, key):
    pattern = r"(?m)^[\"']?" + re.escape(key) + r"[\"']?:\s*\n"
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1:
        raise AssertionError(f"expected one top-level {key} block")
    tail = text[matches[0].end():]
    return re.split(r"(?m)^[^ #\n]", tail, maxsplit=1)[0]


def jobs(name):
    body = top_block(read_workflow(name), "jobs")
    return re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):\s*$", body)


def job(name, ident):
    body = top_block(read_workflow(name), "jobs")
    matches = list(re.finditer(r"(?m)^  " + re.escape(ident) + r":\s*\n", body))
    if len(matches) != 1:
        raise AssertionError(f"{name}: expected one {ident} job")
    return re.split(r"(?m)^  [a-z][a-z0-9_-]*:\s*$",
                    body[matches[0].end():], maxsplit=1)[0]


def steps(name, job_name):
    return re.split(r"(?m)^      - ", job(name, job_name))[1:]


def step(name, job_name, ident):
    found = [block for block in steps(name, job_name)
             if re.search(r"(?m)^(?:        )?id: " + re.escape(ident) + r"$", block)]
    if len(found) != 1:
        raise AssertionError(f"{name}/{job_name}: expected one {ident} step")
    return found[0]


def run_source(block):
    match = re.search(r"(?m)^        run: \|\n", block)
    if match is None:
        raise AssertionError("control must have an explicit literal run block")
    lines = []
    for line in block[match.end():].splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:] if line else "")
    if not any(line.strip() for line in lines):
        raise AssertionError("empty workflow control")
    return "\n".join(lines) + "\n"


def load_step(name, job_name, ident):
    block = step(name, job_name, ident)
    if not re.search(r"(?m)^        shell: python(?: \{0\})?$", block):
        raise AssertionError("workflow control must use explicit Python")
    source = run_source(block)
    scope = {"__name__": "workflow_contract"}
    exec(compile(source, f"<{name}/{job_name}/{ident}>", "exec"), scope)
    return scope, source


def dependencies(block):
    match = re.search(r"(?m)^    needs: (.+)$", block)
    if match is None:
        return []
    value = match[1].strip()
    if value.startswith("[") and value.endswith("]"):
        return [item.strip() for item in value[1:-1].split(",") if item.strip()]
    if re.fullmatch(r"[a-z][a-z0-9_-]*", value):
        return [value]
    raise AssertionError("expected an explicit dependency list")


def oid(label):
    return hashlib.sha1(label.encode("ascii")).hexdigest()


def run_main(scope, source, environment):
    """Execute the real guarded entry point with already-patched I/O seams."""
    tree = ast.parse(source)
    guards = [node for node in tree.body if isinstance(node, ast.If)
              and isinstance(node.test, ast.Compare)
              and isinstance(node.test.left, ast.Name)
              and node.test.left.id == "__name__"
              and len(node.test.comparators) == 1
              and isinstance(node.test.comparators[0], ast.Constant)
              and node.test.comparators[0].value == "__main__"]
    if len(guards) != 1:
        raise AssertionError("expected one guarded workflow entry point")
    entry = ast.Module(body=guards[0].body, type_ignores=[])
    with patch.dict(os.environ, environment, clear=True):
        exec(compile(entry, "<workflow-entry>", "exec"), scope)


def api_controls():
    controls = [(name, ident, control) for name, ident, control in gate_controls()]
    for ident, step_id in (("prepare", "release"), ("publish", "publish")):
        controls.append(("release.yml", ident, load_step("release.yml", ident, step_id)[0]))
    return controls


def job_record(name, ident=1, run_id=501, attempt=2):
    return {"id": ident, "run_id": run_id, "run_attempt": attempt,
            "head_sha": oid("caller-a"), "name": name,
            "status": "completed", "conclusion": "success",
            "steps": [step_record(step, index) for index, step in enumerate(fixture_step_names(name), 1)]}


class ReleaseBundle:
    """Real package/checksum producer, using only synthetic bytes in a tempdir."""
    version = "1.2.3"
    tag = "v1.2.3"
    source_commit = oid("tag-b")
    epoch = 1_700_000_000

    def __init__(self, base):
        self.base = base
        self.workspace = base / "source"
        self.workspace.mkdir()
        (self.workspace / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "1.2.3"\n', encoding="utf-8")
        (self.workspace / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "agent-session-grep-cli"\nversion = "1.2.3"\n',
            encoding="utf-8")
        for name in BUILD_MANIFEST.REQUIRED_DOCUMENTS:
            (self.workspace / name).write_text(f"Synthetic release fixture: {name}\n", encoding="utf-8")
        self.lock_hash = BUILD_MANIFEST.sha256_file(self.workspace / "Cargo.lock")
        metadata = self.workspace / "metadata.json"
        metadata.write_text(json.dumps({
            "version": 1, "workspace_members": ["synthetic-cli"],
            "packages": [{"id": "synthetic-cli", "name": "agent-session-grep-cli",
                          "version": self.version, "source": None, "license": "MIT OR Apache-2.0"}],
            "resolve": {"nodes": [{"id": "synthetic-cli", "dependencies": []}]},
        }), encoding="utf-8")
        self.dist = base / "dist"
        dependency_json, dependency_csv = BUILD_MANIFEST.write_dependency_inventory(
            self.workspace, metadata, self.version, self.dist)
        self.manifests, self.archives = {}, {}
        for target in TARGETS:
            binary = self.workspace / ("agent-session-grep.exe" if "windows" in target else "agent-session-grep")
            binary.write_bytes(f"synthetic non-executable bytes for {target}".encode())
            archive, manifest = BUILD_MANIFEST.package_release(
                workspace=self.workspace, binary=binary,
                dependency_json=dependency_json, dependency_csv=dependency_csv,
                target=target, tag=self.tag, version=self.version,
                source_commit=self.source_commit, source_date_epoch=self.epoch,
                archive_format="zip" if "windows" in target else "tar.gz", output_dir=self.dist)
            self.archives[target], self.manifests[target] = archive, manifest
        self.refresh_checksums()

    def refresh_checksums(self):
        BUILD_MANIFEST.write_checksums(self.dist, self.dist / "SHA256SUMS")

    def change_manifest(self, path, value, target=TARGETS[0]):
        manifest_path = self.manifests[target]
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        node = data
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        self.refresh_checksums()

    def validate(self, control, **overrides):
        arguments = dict(root=self.dist, tag=self.tag, version=self.version,
                         source_commit=self.source_commit, source_date_epoch=self.epoch,
                         cargo_lock_sha256=self.lock_hash)
        arguments.update(overrides)
        return control["validate_artifacts"](**arguments)


@contextlib.contextmanager
def release_bundle():
    with tempfile.TemporaryDirectory(prefix="workflow-contract-") as directory:
        yield ReleaseBundle(Path(directory))


RELEASE_INPUTS = ("Cargo.lock", "Cargo.toml", "README.md", "LICENSE-MIT", "LICENSE-APACHE",
                  "CHANGELOG.md", "SECURITY.md", "NOTICE")


@contextlib.contextmanager
def git_release_bundle(overrides=None):
    """A plumbing-only temporary Git fixture, never the product repository."""
    with release_bundle() as bundle:
        blobs = {name: (bundle.workspace / name).read_bytes().replace(b"\r\n", b"\n")
                 for name in RELEASE_INPUTS}
        blobs.update(overrides or {})
        environment = dict(os.environ)
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
            environment.pop(key, None)
        environment.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "test@example.invalid",
                            "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "test@example.invalid",
                            "GIT_AUTHOR_DATE": f"{bundle.epoch} +0000", "GIT_COMMITTER_DATE": f"{bundle.epoch} +0000"})

        def git(*arguments, data=None):
            return subprocess.run(["git", *arguments], cwd=bundle.workspace, env=environment,
                                  input=data, capture_output=True, check=True).stdout

        git("init", "-q")
        objects = {name: git("hash-object", "-w", "--stdin", data=content).strip()
                   for name, content in blobs.items()}
        tree = git("mktree", "-z", data=b"".join(
            b"100644 blob " + objects[name] + b"\t" + name.encode() + b"\0" for name in sorted(blobs))).strip()
        source = git("-c", "commit.gpgsign=false", "commit-tree", tree.decode(),
                     data=b"Synthetic release input fixture\n").decode().strip()
        # Bind detached HEAD without invoking reference-transaction hooks.
        (bundle.workspace / ".git" / "HEAD").write_bytes(source.encode() + b"\n")
        git("read-tree", source)
        bundle.source_commit, bundle.git_inputs, bundle.git_objects = source, blobs, objects
        bundle.git_environment = environment
        bundle.lock_hash = hashlib.sha256(blobs["Cargo.lock"]).hexdigest()
        for name, content in blobs.items():
            (bundle.workspace / name).write_bytes(content)
        yield bundle


def checkout_release_inputs(bundle, workspace, crlf):
    environment = {**bundle.git_environment, "GIT_DIR": str(bundle.workspace / ".git"),
                   "GIT_WORK_TREE": str(workspace)}
    subprocess.run(["git", "-c", "core.autocrlf=" + ("true" if crlf else "false"),
                    "-c", "core.eol=lf", "checkout-index", "--force", "--", *RELEASE_INPUTS],
                   cwd=workspace, env=environment, capture_output=True, check=True)


def package_checkout_variants(bundle, windows_workspace):
    for target in TARGETS:
        workspace = windows_workspace if target == TARGETS[0] else bundle.workspace
        binary = workspace / ("agent-session-grep.exe" if target == TARGETS[0] else "agent-session-grep")
        binary.write_bytes(("synthetic non-executable " + target).encode())
        BUILD_MANIFEST.package_release(
            workspace=workspace, binary=binary,
            dependency_json=bundle.dist / "THIRD-PARTY-DEPENDENCIES.json",
            dependency_csv=bundle.dist / "THIRD-PARTY-DEPENDENCIES.csv",
            target=target, tag=bundle.tag, version=bundle.version, source_commit=bundle.source_commit,
            source_date_epoch=bundle.epoch, archive_format="zip" if target == TARGETS[0] else "tar.gz",
            output_dir=bundle.dist)
    bundle.refresh_checksums()


def artifact_controls():
    return [(name, ident, load_step(name, ident, step_id)[0]) for name, ident, step_id in (
        ("release.yml", "assemble", "validate_artifacts"),
        ("release-verify.yml", "assemble", "validate_artifacts"),
        ("release.yml", "publish", "publish"),
    )]


def release_record(tag="v0.9.0", ident=7, draft=False, assets=None):
    return {"id": ident, "tag_name": tag, "draft": draft, "assets": assets or []}


def absence_responses(tag="v1.2.3"):
    return {
        "repos/sample/project": {"id": 123, "full_name": "sample/project", "permissions": {"push": True}},
        f"repos/sample/project/releases/tags/{tag}": None,
        "repos/sample/project/releases?per_page=100&page=1": [],
    }


def make_downloads(bundle, prefix, targets=TARGETS):
    artifacts, inputs, output = (bundle.base / name for name in ("artifacts", "release-inputs", "assembled"))
    artifacts.mkdir()
    inputs.mkdir()
    for target in targets:
        folder = artifacts / (prefix + target)
        folder.mkdir()
        for path in (bundle.archives[target], bundle.manifests[target]):
            (folder / path.name).write_bytes(path.read_bytes())
        BUILD_MANIFEST.write_checksums(folder, folder / "SHA256SUMS")
    for name in ("THIRD-PARTY-DEPENDENCIES.json", "THIRD-PARTY-DEPENDENCIES.csv"):
        (inputs / name).write_bytes((bundle.dist / name).read_bytes())
    return artifacts, inputs, output


def publish_environment(bundle):
    return {
        "GH_REPO": "sample/project", "REPOSITORY_ID": "123", "GITHUB_SHA": oid("caller-a"),
        "NEEDS_JSON": json.dumps({name: {"result": "success"} for name in ("prepare", "quality", "build", "assemble", "gate")}),
        "RELEASE_TAG": bundle.tag, "VERSION": bundle.version, "SOURCE_COMMIT": bundle.source_commit,
        "SOURCE_DATE_EPOCH": str(bundle.epoch), "CARGO_LOCK_SHA256": bundle.lock_hash,
        "TAG_OBJECT": bundle.source_commit,
    }


@contextlib.contextmanager
def gate_event(event_name, event):
    with tempfile.TemporaryDirectory(prefix="workflow-event-") as directory:
        path = Path(directory) / "event.json"
        path.write_text(json.dumps(event), encoding="utf-8")
        yield {"EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(path)}


def expected_gate_leaves(name):
    if name == "ci.yml":
        leaves = [f"{kind} ({runner})" for kind in ("test", "installer smoke")
                  for runner in ("ubuntu-latest", "windows-latest", "macos-latest")]
        return leaves + ["Cargo dependency audit", "validate exact CI source", "resolve audit source"]
    kind = "build" if name == "release.yml" else "verify"
    return [kind + " " + target for target in TARGETS] + [
        "resolve exact source and release inputs", "validate complete four-target unsigned bundle", "all required quality checks"]


def gate_environment(name, checkout_sha):
    needs = ["source", "test", "installer", "security"] if name == "ci.yml" else ["prepare", "quality", "build", "assemble"]
    return {"NEEDS_JSON": json.dumps({dep: {"result": "success"} for dep in needs}),
            "GITHUB_RUN_ID": "501", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_REPOSITORY": "sample/project",
            "GITHUB_SHA": checkout_sha, "SOURCE_COMMIT": checkout_sha}


class WorkflowWiringTests(unittest.TestCase):
    def test_ci_is_reusable_only_and_requires_source_commit(self):
        trigger = top_block(read_workflow("ci.yml"), "on")
        self.assertEqual(re.findall(r"(?m)^  ([a-z_]+):", trigger), ["workflow_call"])
        self.assertRegex(trigger, r"(?ms)^      source_commit:\n(?:(?:        .*)?\n)*?        required: true$")
        self.assertRegex(trigger, r"(?ms)^      source_commit:\n(?:(?:        .*)?\n)*?        type: string$")

    def test_verify_is_the_single_unfiltered_quality_entry(self):
        trigger = top_block(read_workflow("release-verify.yml"), "on")
        self.assertCountEqual(re.findall(r"(?m)^  ([a-z_]+):", trigger),
                              ["pull_request", "push", "workflow_dispatch"])
        self.assertRegex(trigger, r"(?m)^    branches: \[main\]$")
        self.assertNotRegex(trigger, r"(?m)^\s+(?:paths|paths-ignore|tags|tags-ignore):")
        callers = []
        for path in sorted(WORKFLOW_DIR.glob("*.yml")):
            text = read_workflow(path.name)
            count = text.count("uses: ./.github/workflows/ci.yml")
            callers.extend([path.name] * count)
        self.assertCountEqual(callers, ["release.yml", "release-verify.yml"])

    def test_both_callers_bind_quality_build_and_assembly_to_prepare(self):
        for name in ("release.yml", "release-verify.yml"):
            with self.subTest(workflow=name):
                quality = job(name, "quality")
                self.assertEqual(dependencies(quality), ["prepare"])
                self.assertIn("uses: ./.github/workflows/ci.yml", quality)
                self.assertIn("source_commit: ${{ needs.prepare.outputs.source_commit }}", quality)
                self.assertTrue({"prepare", "quality"}.issubset(dependencies(job(name, "build"))))
                self.assertIn("prepare", dependencies(job(name, "assemble")))
                for ident in ("build", "assemble"):
                    checkouts = [part for part in steps(name, ident)
                                 if "uses: actions/checkout@" in part]
                    self.assertEqual(len(checkouts), 1)
                    self.assertIn("ref: ${{ needs.prepare.outputs.source_commit }}", checkouts[0])
                    self.assertIn("persist-credentials: false", checkouts[0])
                    step(name, ident, "assert_source")

    def test_reusable_ci_has_no_caller_sha_fallback(self):
        text = read_workflow("ci.yml")
        self.assertNotIn("github.sha", text)
        for ident in jobs("ci.yml"):
            for block in steps("ci.yml", ident):
                if "uses: actions/checkout@" not in block:
                    continue
                self.assertIn("ref: ${{ inputs.source_commit }}", block)
                self.assertIn("persist-credentials: false", block)
                step("ci.yml", ident, "assert_source")

    def test_data_never_becomes_inline_script_source(self):
        for name in WORKFLOWS:
            for ident in jobs(name):
                for block in steps(name, ident):
                    if "        run: |\n" in block:
                        with self.subTest(workflow=name, job=ident, step=block.splitlines()[0]):
                            self.assertNotIn("${{", run_source(block))

    def test_security_reuses_audit_without_duplicate_pr_entry(self):
        trigger = top_block(read_workflow("security-audit.yml"), "on")
        self.assertCountEqual(re.findall(r"(?m)^  ([a-z_]+):", trigger),
                              ["workflow_call", "workflow_dispatch", "schedule"])
        self.assertIn("uses: ./.github/workflows/security-audit.yml", read_workflow("ci.yml"))
        audit = read_workflow("security-audit.yml")
        for command in ("cargo deny check", "cargo audit --file Cargo.lock", "zero-egress"):
            self.assertIn(command, audit)

    def test_publish_is_the_only_write_job_and_has_no_candidate_checkout(self):
        for name in WORKFLOWS:
            for ident in jobs(name):
                block = job(name, ident)
                if (name, ident) == ("release.yml", "publish"):
                    self.assertIn("contents: write", block)
                    self.assertNotIn("uses: actions/checkout@", block)
                else:
                    self.assertNotRegex(block, r": (?:write|write-all)\b")
        publish = job("release.yml", "publish")
        for command in ("--clobber", "gh release upload", "gh release delete", "git push", "git tag"):
            self.assertNotIn(command, publish)
        self.assertIn("--verify-tag", publish)


class SourceCommitControlTests(unittest.TestCase):
    def test_full_nonzero_lowercase_sha_is_preserved(self):
        control, _ = load_step("release.yml", "prepare", "release")
        self.assertEqual(control["validate_source_commit"](oid("tag-b")), oid("tag-b"))

    def test_invalid_empty_zero_or_executable_sha_is_rejected(self):
        control, _ = load_step("release.yml", "prepare", "release")
        for value in (None, "", "0" * 40, "A" * 40, "a" * 39, "b" * 41,
                      "main", "HEAD", "$(echo injected)", oid("tag-b") + "\n", 123):
            with self.subTest(value=value), self.assertRaises(ValueError):
                control["validate_source_commit"](value)


class FakeAPI:
    """Strict endpoint fixtures: an unspecified request is a test failure."""
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, path, allow_not_found=False):
        path = path.removeprefix("/")
        self.calls.append((path, allow_not_found))
        if path not in self.responses:
            raise AssertionError(f"unexpected API request: {path}")
        value = self.responses[path]
        if isinstance(value, BaseException):
            raise value
        if value is None and not allow_not_found:
            raise ValueError("required API object is unavailable")
        return copy.deepcopy(value)


def tag_response(tag="v1.2.3", commit=None, kind="commit"):
    return {"ref": f"refs/tags/{tag}",
            "object": {"type": kind, "sha": commit or oid("tag-b")}}


def gate_controls():
    result = []
    for name in ("ci.yml", "release.yml", "release-verify.yml"):
        found = []
        for ident in jobs(name):
            if any(re.search(r"(?m)^(?:        )?id: gate$", part)
                   for part in steps(name, ident)):
                found.append((name, ident, load_step(name, ident, "gate")[0]))
        if not found:
            raise AssertionError(f"{name}: missing explicit aggregate gate")
        result.extend(found)
    return result


class TagControlTests(unittest.TestCase):
    def setUp(self):
        self.control, self.source = load_step("release.yml", "prepare", "release")
        self.repo = "sample/project"
        self.tag = "v1.2.3"
        self.ref_path = f"repos/{self.repo}/git/ref/tags/{self.tag}"

    def resolve(self, api, tag=None):
        return self.control["resolve_tag"](api, self.repo, tag or self.tag)

    def test_push_and_dispatch_select_tag_as_literal_data(self):
        select = self.control["select_tag"]
        self.assertEqual(select("push", "refs/tags/v1.2.3", {}), "v1.2.3")
        self.assertEqual(select("workflow_dispatch", "refs/heads/main",
                                {"tag": "v1.2.3-rc.1+build.7"}),
                         "v1.2.3-rc.1+build.7")

    def test_unsupported_event_branch_ref_and_missing_input_reject(self):
        select = self.control["select_tag"]
        for args in (("pull_request", "refs/pull/1/merge", {}),
                     ("push", "refs/heads/v1.2.3", {}),
                     ("workflow_dispatch", "refs/heads/main", {}),
                     ("workflow_dispatch", "refs/heads/main", {"tag": None}),
                     ("workflow_dispatch", "refs/heads/main", {"tag": ""})):
            with self.subTest(args=args), self.assertRaises(ValueError):
                select(*args)

    def test_hostile_tag_never_executes_shell_or_reaches_api(self):
        values = ("v1.2.3'; echo injected", "v1.2.3$(echo injected)",
                  "v1.2.3`echo injected`", "v1.2.3\nsource_commit=bad",
                  "--upload-pack=unexpected", "../v1.2.3", " v1.2.3", "v1.2.3\0")
        for value in values:
            api = FakeAPI({})
            with self.subTest(value=value), patch("subprocess.run") as run, \
                    patch("subprocess.check_output") as output, patch("os.system") as shell:
                with self.assertRaises(ValueError):
                    self.control["select_tag"]("workflow_dispatch", "refs/heads/main", {"tag": value})
                with self.assertRaises(ValueError):
                    self.resolve(api, value)
                self.assertEqual(api.calls, [])
                run.assert_not_called()
                output.assert_not_called()
                shell.assert_not_called()

    def test_lightweight_tag_uses_exact_ref_not_caller_a(self):
        api = FakeAPI({self.ref_path: tag_response()})
        with patch.dict(os.environ, {"GITHUB_SHA": oid("caller-a")}):
            resolved = self.resolve(api)
        self.assertEqual(resolved, {"tag_object": oid("tag-b"), "source_commit": oid("tag-b")})
        self.assertNotEqual(resolved["source_commit"], oid("caller-a"))
        self.assertEqual([path for path, _ in api.calls], [self.ref_path])

    def test_prefix_ref_match_and_reference_lists_are_rejected(self):
        for response in (tag_response("v1.2.30"), tag_response("v1.2.3-extra"),
                         [tag_response()], {"object": tag_response()["object"]}):
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.resolve(FakeAPI({self.ref_path: response}))

    def test_annotated_ref_preserves_object_identity_while_peeling(self):
        observed = []
        for label in ("original-tag-object", "moved-tag-object"):
            outer, inner, commit = oid(label), oid("inner-tag"), oid("tag-b")
            api = FakeAPI({
                self.ref_path: tag_response(commit=outer, kind="tag"),
                f"repos/{self.repo}/git/tags/{outer}": {
                    "sha": outer, "tag": self.tag, "object": {"type": "tag", "sha": inner}},
                f"repos/{self.repo}/git/tags/{inner}": {
                    "sha": inner, "tag": self.tag, "object": {"type": "commit", "sha": commit}},
            })
            result = self.resolve(api)
            self.assertEqual(result, {"tag_object": outer, "source_commit": commit})
            observed.append(result)
        self.assertEqual(observed[0]["source_commit"], observed[1]["source_commit"])
        self.assertNotEqual(observed[0]["tag_object"], observed[1]["tag_object"])

    def test_missing_remote_tag_and_unavailable_api_are_not_creation(self):
        for response in (None, URLError("synthetic unavailable"),
                         HTTPError("https://api.github.com/synthetic", 403, "denied", {}, None),
                         HTTPError("https://api.github.com/synthetic", 500, "failure", {}, None)):
            with self.subTest(response=type(response).__name__), self.assertRaises((ValueError, URLError)):
                self.resolve(FakeAPI({self.ref_path: response}))

    def test_invalid_objects_and_annotated_cycles_fail_closed(self):
        for response in ({}, {"ref": f"refs/tags/{self.tag}"},
                         tag_response(commit="0" * 40), tag_response(commit="A" * 40),
                         tag_response(kind="tree"), tag_response(commit="short")):
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.resolve(FakeAPI({self.ref_path: response}))
        outer = oid("cyclic-tag")
        api = FakeAPI({self.ref_path: tag_response(commit=outer, kind="tag"),
                       f"repos/{self.repo}/git/tags/{outer}": {
                           "sha": outer, "tag": self.tag, "object": {"type": "tag", "sha": outer}}})
        with self.assertRaises(ValueError):
            self.resolve(api)
        self.assertLessEqual(len(api.calls), 3, "cycle must stop before repeated requests")


class DependencyGateTests(unittest.TestCase):
    def test_every_mandatory_dependency_must_actually_succeed(self):
        expected = ["prepare", "quality", "build", "assemble"]
        good = {name: {"result": "success", "outputs": {}} for name in expected}
        for workflow, ident, control in gate_controls():
            with self.subTest(workflow=workflow, job=ident):
                self.assertIsNone(control["require_success"](good, expected))
                for dependency in expected:
                    for state in ("failure", "skipped", "cancelled", "neutral", "timed_out",
                                  "action_required", "queued", "in_progress", "", None):
                        changed = copy.deepcopy(good)
                        changed[dependency]["result"] = state
                        with self.subTest(dependency=dependency, state=state), self.assertRaises(ValueError):
                            control["require_success"](changed, expected)

    def test_missing_extra_or_malformed_dependency_results_reject(self):
        expected = ["prepare", "quality", "build", "assemble"]
        good = {name: {"result": "success"} for name in expected}
        cases = [None, [], {}, {**good, "unexpected": {"result": "success"}}]
        for name in expected:
            missing = copy.deepcopy(good)
            del missing[name]
            cases.append(missing)
            for value in ({}, None, "success", {"conclusion": "success"}):
                cases.append({**good, name: value})
        for workflow, ident, control in gate_controls():
            for changed in cases:
                with self.subTest(workflow=workflow, job=ident, needs=changed), self.assertRaises(ValueError):
                    control["require_success"](changed, expected)


class ReusableSourceTests(unittest.TestCase):
    def test_ci_entry_rejects_missing_empty_or_invalid_source_without_fallback(self):
        control, source = load_step("ci.yml", "source", "source")
        for value in (None, "", "0" * 40, "A" * 40, "HEAD"):
            env = {"GITHUB_SHA": oid("caller-a")}
            if value is not None:
                env["SOURCE_COMMIT"] = value
            with self.subTest(value=value), self.assertRaises((KeyError, ValueError)):
                run_main(control, source, env)
        run_main(control, source, {"SOURCE_COMMIT": oid("tag-b"), "GITHUB_SHA": oid("caller-a")})

    def test_checkout_assertions_accept_b_and_reject_caller_a(self):
        required = (("ci.yml", "test"), ("ci.yml", "installer"),
                    ("security-audit.yml", "dependency-audit"),
                    ("release.yml", "build"), ("release.yml", "assemble"),
                    ("release-verify.yml", "build"), ("release-verify.yml", "assemble"))
        for name, ident in required:
            control, _ = load_step(name, ident, "assert_source")
            with self.subTest(workflow=name, job=ident):
                with patch("subprocess.check_output", return_value=oid("tag-b") + "\n") as git:
                    self.assertIsNone(control["assert_source"](oid("tag-b")))
                    git.assert_called_once_with(["git", "rev-parse", "HEAD"], text=True)
                with patch("subprocess.check_output", return_value=oid("caller-a") + "\n"):
                    with self.assertRaises(ValueError):
                        control["assert_source"](oid("tag-b"))
                for value in (None, "", "0" * 40, "HEAD", "$(echo injected)"):
                    with patch("subprocess.check_output") as git, self.assertRaises(ValueError):
                        control["assert_source"](value)
                    git.assert_not_called()

    def test_audit_uses_supplied_source_even_for_dispatch_caller(self):
        control, _ = load_step("security-audit.yml", "source", "source")
        select = control["select_source"]
        for event in ("pull_request", "push", "workflow_dispatch", "schedule"):
            self.assertEqual(select({"source_commit": oid("tag-b")}, event, oid("caller-a")), oid("tag-b"))
            for value in (None, "", "0" * 40, "A" * 40, "main"):
                with self.subTest(event=event, value=value), self.assertRaises(ValueError):
                    select({"source_commit": value}, event, oid("caller-a"))
        for event in ("pull_request", "push"):
            with self.subTest(event=event), self.assertRaises(ValueError):
                select({}, event, oid("caller-a"))
        for invalid in ([], 0, False, "nonempty scalar", {"unexpected": "value"}):
            with self.subTest(inputs=invalid), self.assertRaises(ValueError):
                select(invalid, "workflow_dispatch", oid("caller-a"))
        # A reusable call may inherit the caller's workflow_dispatch keys.
        # Only the declared source key affects checkout; metadata stays data.
        for event in ("pull_request", "push", "workflow_dispatch", "schedule"):
            self.assertEqual(select({"source_commit": oid("tag-b"), "tag": "v1.2.3",
                                     "unexpected": "$(echo injected)\nsource_commit=wrong"},
                                    event, oid("caller-a")), oid("tag-b"))
        for event in ("schedule", "workflow_dispatch"):
            for unavailable in (None, "", {}):
                self.assertEqual(select(unavailable, event, oid("caller-a")), oid("caller-a"))


class InstalledCommandControlTests(unittest.TestCase):
    def test_every_windows_installed_command_must_succeed(self):
        control, source = load_step("ci.yml", "installer", "invoke_installed")
        expected = [
            ["./ci-prefix/agent-session-grep.exe", "--version"],
            ["./ci-prefix/asg.exe", "--version"],
            ["./ci-prefix/agent-session-grep.exe", "--robot", "config", "paths"],
            ["./ci-prefix/asg.exe", "--robot", "config", "paths"],
        ]
        real_run = subprocess.run
        for failure in (None, 0, 1, 2, 3):
            calls = []

            def synthetic_native(argv, **kwargs):
                index = len(calls)
                calls.append((argv, kwargs))
                # Exercise real native exit handling without needing an installed
                # Windows product binary on the other quality-matrix platforms.
                code = 17 if index == failure else 0
                # Isolate the stub without changing captured workflow arguments.
                probe_kwargs = {"env": {}, **kwargs}
                return real_run([sys.executable, "-c", f"raise SystemExit({code})"], **probe_kwargs)

            with self.subTest(failed_command=failure), patch("subprocess.run", side_effect=synthetic_native):
                if failure is None:
                    run_main(control, source, {})
                else:
                    with self.assertRaises(subprocess.CalledProcessError) as error:
                        run_main(control, source, {})
                    self.assertEqual(error.exception.returncode, 17)
                count = len(expected) if failure is None else failure + 1
                self.assertEqual(calls, [(argv, {"check": True}) for argv in expected[:count]])


    def test_windows_uninstall_checks_each_script_exit(self):
        control, source = load_step("ci.yml", "installer", "uninstall_twice")
        real_run = subprocess.run
        for failure in (None, 0, 1):
            with self.subTest(failed_call=failure), tempfile.TemporaryDirectory(prefix="workflow-uninstall-") as directory:
                calls = []
                expected = ["pwsh", "-NoProfile", "-NonInteractive", "-File",
                            "./scripts/install/uninstall.ps1", "-Prefix", str(Path(directory, "ci-prefix").resolve())]

                def synthetic_script(argv, **kwargs):
                    index = len(calls)
                    calls.append((argv, kwargs))
                    probe_kwargs = {"env": {}, **kwargs}
                    return real_run([sys.executable, "-c", f"raise SystemExit({17 if index == failure else 0})"], **probe_kwargs)

                with contextlib.chdir(directory), patch("subprocess.run", side_effect=synthetic_script):
                    if failure is None:
                        run_main(control, source, {})
                    else:
                        with self.assertRaises(subprocess.CalledProcessError) as error:
                            run_main(control, source, {})
                        self.assertEqual(error.exception.returncode, 17)
                count = 2 if failure is None else failure + 1
                self.assertEqual(calls, [(expected, {"check": True})] * count)

    def test_windows_uninstall_rejects_each_remaining_command_before_retry(self):
        control, source = load_step("ci.yml", "installer", "uninstall_twice")
        for binary in ("agent-session-grep.exe", "asg.exe"):
            with self.subTest(binary=binary), tempfile.TemporaryDirectory(prefix="workflow-uninstall-") as directory:
                prefix = Path(directory, "ci-prefix")
                prefix.mkdir()
                remaining = prefix / binary
                remaining.write_bytes(b"synthetic installed command")
                with contextlib.chdir(directory), patch("subprocess.run") as command, self.assertRaises(ValueError):
                    run_main(control, source, {})
                command.assert_called_once()
                self.assertEqual(remaining.read_bytes(), b"synthetic installed command")


    def test_native_probes_use_explicit_environment_in_fresh_process(self):
        # Select only the two existing exit tests, not this containing suite.
        # Bootstrap imports normally: unittest.mock needs Windows system variables.
        # Only exit-only probes use an empty environment. The spy catches omitted
        # env even on platforms where implicit inheritance happens to work.
        probe = """
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
from test_workflow_contracts import InstalledCommandControlTests

real_run = subprocess.run

def checked_native(argv, **kwargs):
    if kwargs.get("env") != {}:
        raise AssertionError("exit-only native probes must receive explicit env={}")
    return real_run(argv, **kwargs)

methods = (
    "test_every_windows_installed_command_must_succeed",
    "test_windows_uninstall_checks_each_script_exit",
)
suite = unittest.TestSuite(InstalledCommandControlTests(name) for name in methods)
with patch("subprocess.run", side_effect=checked_native):
    result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.testsRun != len(methods) or result.skipped:
    raise AssertionError("both original native-exit tests must run without skips")
raise SystemExit(not result.wasSuccessful())
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", probe, str(Path(__file__).resolve().parent)],
            env=os.environ.copy(), capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")


class ZeroEgressControlTests(unittest.TestCase):
    crates = ("reqwest", "hyper", "ureq", "isahc", "surf", "attohttpc", "tiny_http",
              "rouille", "warp", "axum", "tokio", "async-std")
    socket_argv = ["grep", "-rlEZ", "TcpListener|TcpStream|TcpSocket|UdpSocket|std::net",
                   "crates", "--include=*.rs"]

    def test_no_matches_and_only_exact_allowed_source_are_success(self):
        control, source = load_step("security-audit.yml", "dependency-audit", "zero_egress")
        for output in ("", "crates/agent-session-grep-cli/src/serve.rs\0crates/sample/tests/socket.rs\0"):
            calls = []
            def grep(argv, **kwargs):
                calls.append((argv, kwargs))
                if argv == self.socket_argv:
                    return subprocess.CompletedProcess(argv, 0 if output else 1, output, "")
                return subprocess.CompletedProcess(argv, 1, "", "")
            with self.subTest(output=output), patch("subprocess.run", side_effect=grep):
                run_main(control, source, {})
            expected = [["grep", "-q", f'^name = "{crate}"', "Cargo.lock"] for crate in self.crates]
            self.assertEqual(calls, [(argv, {"capture_output": True, "text": True}) for argv in [*expected, self.socket_argv]])

    def test_errors_or_missing_grep_never_become_no_matches(self):
        control, source = load_step("security-audit.yml", "dependency-audit", "zero_egress")
        for failing_call in (0, len(self.crates)):
            for failure in (2, 127, -1, FileNotFoundError("synthetic missing grep")):
                calls = []
                def grep(argv, **kwargs):
                    index = len(calls)
                    calls.append(argv)
                    if index == failing_call:
                        if isinstance(failure, Exception):
                            raise failure
                        return subprocess.CompletedProcess(argv, failure, "", "synthetic raw diagnostic")
                    return subprocess.CompletedProcess(argv, 1, "", "")
                with self.subTest(call=failing_call, failure=type(failure).__name__ if isinstance(failure, Exception) else failure), \
                        patch("subprocess.run", side_effect=grep):
                    with self.assertRaises((ValueError, OSError)) as error:
                        run_main(control, source, {})
                    self.assertNotIn("synthetic raw diagnostic", str(error.exception))
                    self.assertEqual(len(calls), failing_call + 1)

    def test_every_forbidden_dependency_and_nonexact_socket_path_rejects(self):
        control, source = load_step("security-audit.yml", "dependency-audit", "zero_egress")
        for crate in self.crates:
            def grep(argv, **kwargs):
                match = argv == ["grep", "-q", f'^name = "{crate}"', "Cargo.lock"]
                return subprocess.CompletedProcess(argv, 0 if match else 1, "", "")
            with self.subTest(crate=crate), patch("subprocess.run", side_effect=grep), self.assertRaises(ValueError):
                run_main(control, source, {})
        for output in ("crates/sample/src/socket.rs\0",
                       "crates/agent-session-grep-cli/src/serve.rs.extra.rs\0",
                       "crates/agent-session-grep-cli/src/serve.rs\nextra.rs\0",
                       "crates/agent-session-grep-cli/src/serve.rs\n", ""):
            def grep(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0 if argv == self.socket_argv else 1,
                                                   output if argv == self.socket_argv else "", "")
            with self.subTest(output=output), patch("subprocess.run", side_effect=grep), self.assertRaises(ValueError):
                run_main(control, source, {})


class GitHubTransportTests(unittest.TestCase):
    environment = {"GITHUB_API_URL": "https://api.github.com", "GH_TOKEN": "offline-synthetic"}

    def test_only_confirmed_404_can_mean_absence(self):
        for name, ident, control in api_controls():
            for status in (403, 404, 422, 429, 500, 503):
                for allowed in (False, True):
                    error = HTTPError("https://api.github.com/synthetic", status, "synthetic", {}, None)
                    with self.subTest(workflow=name, job=ident, status=status, allowed=allowed), \
                            patch.dict(os.environ, self.environment, clear=True), \
                            patch("urllib.request.build_opener") as opener:
                        opener.return_value.open.side_effect = error
                        if status == 404 and allowed:
                            self.assertIsNone(control["api_get"]("/repos/sample/project/releases/tags/v1.2.3", True))
                        else:
                            with self.assertRaises(ValueError):
                                control["api_get"]("/repos/sample/project/releases/tags/v1.2.3", allowed)

    def test_network_timeout_bad_json_and_null_200_are_not_absence(self):
        for name, ident, control in api_controls():
            for failure in (URLError("synthetic unavailable"), TimeoutError("synthetic timeout")):
                with self.subTest(workflow=name, job=ident, failure=type(failure).__name__), \
                        patch.dict(os.environ, self.environment, clear=True), \
                        patch("urllib.request.build_opener") as opener:
                    opener.return_value.open.side_effect = failure
                    with self.assertRaises(ValueError):
                        control["api_get"]("/repos/sample/project/releases/tags/v1.2.3", True)
            for data in (b"null", b'"unexpected"', b"123", b"true", b"{", b"\xff", b'{"id":1,"id":2}'):
                with self.subTest(workflow=name, job=ident, data=data), \
                        patch.dict(os.environ, self.environment, clear=True), \
                        patch("urllib.request.build_opener") as opener:
                    response = io.BytesIO(data)
                    response.status = 200
                    opener.return_value.open.return_value = response
                    with self.assertRaises(ValueError):
                        control["api_get"]("/repos/sample/project/releases/tags/v1.2.3", True)

    def test_successful_json_and_headers_use_only_read_requests(self):
        for name, ident, control in api_controls():
            for data in ({"id": 123}, []):
                with self.subTest(workflow=name, job=ident, data=data), \
                        patch.dict(os.environ, self.environment, clear=True), \
                        patch("urllib.request.build_opener") as opener:
                    response = io.BytesIO(json.dumps(data).encode())
                    response.status = 200
                    opener.return_value.open.return_value = response
                    self.assertEqual(control["api_get"]("/repos/sample/project/releases"), data)
                    request = opener.return_value.open.call_args.args[0]
                    self.assertEqual(request.get_method(), "GET")
                    self.assertEqual(request.full_url, "https://api.github.com/repos/sample/project/releases")
                    self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 30)
            with self.subTest(workflow=name, job=ident), self.assertRaises(ValueError):
                control["NoRedirect"]().redirect_request(None, None, 302, "synthetic", {}, "https://other.invalid/")


class RunAttemptJobTests(unittest.TestCase):
    def test_matrix_jobs_bind_caller_a_not_prepared_source_b(self):
        expected = [f"build {target}" for target in TARGETS]
        good = [job_record(name, index) for index, name in enumerate(expected, 1)]
        for workflow, ident, control in gate_controls():
            with self.subTest(workflow=workflow, job=ident):
                self.assertIsNone(control["require_jobs"](good, expected, 501, 2, oid("caller-a")))
                for field, values in {
                    "run_id": (None, 502, True, 501.0),
                    "run_attempt": (None, 1, True, 2.0),
                    "head_sha": (None, oid("tag-b"), oid("other-caller")),
                    "status": (None, "queued", "in_progress"),
                    "conclusion": (None, "failure", "skipped", "cancelled", "neutral", "timed_out"),
                }.items():
                    for value in values:
                        changed = copy.deepcopy(good)
                        changed[2][field] = value
                        with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                            control["require_jobs"](changed, expected, 501, 2, oid("caller-a"))

    def test_exact_leaf_inventory_rejects_missing_duplicate_stale_or_wrong_prefix(self):
        expected = ["test (ubuntu-latest)", "Cargo dependency audit"]
        good = [job_record("required CI quality gates / test (ubuntu-latest)", 1),
                job_record("required CI quality gates / required security audit / Cargo dependency audit", 2)]
        for workflow, ident, control in gate_controls():
            with self.subTest(workflow=workflow, job=ident):
                control["require_jobs"](good, expected, 501, 2, oid("caller-a"))
                cases = [[], good[:1], good + [job_record(expected[0], 3)],
                         [good[0], {**good[1], "id": 1}],
                         [{**good[0], "name": "unrelated workflow / " + expected[0]}, good[1]],
                         [None], [{"id": 1}], [{**good[0], "id": True}, good[1]]]
                for changed in cases:
                    with self.subTest(jobs=changed), self.assertRaises(ValueError):
                        control["require_jobs"](changed, expected, 501, 2, oid("caller-a"))
                for invalid in ([], expected + [expected[0]]):
                    with self.subTest(expected=invalid), self.assertRaises(ValueError):
                        control["require_jobs"](good, invalid, 501, 2, oid("caller-a"))

    def test_job_listing_consumes_all_run_attempt_pages(self):
        records = [job_record(f"synthetic job {index}", index) for index in range(1, 104)]
        base = "repos/sample/project/actions/runs/501/attempts/2/jobs?per_page=100&page="
        for workflow, ident, control in gate_controls():
            api = FakeAPI({base + "1": {"total_count": 103, "jobs": records[:100]},
                           base + "2": {"total_count": 103, "jobs": records[100:]}})
            with self.subTest(workflow=workflow, job=ident):
                self.assertEqual(control["load_jobs"](api, "sample/project", 501, 2), records)
                self.assertEqual([path for path, _ in api.calls], [base + "1", base + "2"])

    def test_job_listing_rejects_incomplete_duplicate_changed_or_malformed_pages(self):
        record = job_record("synthetic", 1)
        base = "repos/sample/project/actions/runs/501/attempts/2/jobs?per_page=100&page="
        page1 = {"total_count": 2, "jobs": [record]}
        second_pages = ({"total_count": 2, "jobs": []},
                        {"total_count": 2, "jobs": [record]},
                        {"total_count": 3, "jobs": [job_record("other", 2)]},
                        {"total_count": 2, "jobs": None}, None,
                        URLError("synthetic unavailable"),
                        HTTPError("https://api.github.com/synthetic", 403, "denied", {}, None),
                        HTTPError("https://api.github.com/synthetic", 500, "failure", {}, None))
        for workflow, ident, control in gate_controls():
            for page2 in second_pages:
                with self.subTest(workflow=workflow, job=ident, page=page2), self.assertRaises((ValueError, URLError)):
                    control["load_jobs"](FakeAPI({base + "1": page1, base + "2": page2}),
                                            "sample/project", 501, 2)
            for first in ({}, [], {"total_count": True, "jobs": []},
                          {"total_count": -1, "jobs": []}, {"total_count": 0, "jobs": [record]},
                          {"total_count": 1, "jobs": [None]},
                          {"total_count": 1, "jobs": [{"id": True}]}):
                with self.subTest(workflow=workflow, job=ident, first=first), self.assertRaises(ValueError):
                    control["load_jobs"](FakeAPI({base + "1": first}), "sample/project", 501, 2)


class VersionControlTests(unittest.TestCase):
    def test_binary_version_is_exact_not_a_substring(self):
        for name in ("release.yml", "release-verify.yml"):
            control, _ = load_step(name, "build", "verify_binary")
            validate = control["validate_binary_version"]
            for suffix in ("", "\n", "\r\n"):
                self.assertIsNone(validate("agent-session-grep 1.2.3" + suffix, "1.2.3"))
            for reported in ("", None, "agent-session-grep 11.2.3", "agent-session-grep 1.2.30",
                             "agent-session-grep 1.2.3-extra", "asg 1.2.3", "other 1.2.3",
                             "agent-session-grep 1.2.3\nextra", " agent-session-grep 1.2.3",
                             "agent-session-grep-cli 1.2.3", "agent-session-grep-cli 1.2.3\n",
                             "agent-session-grep 1.2.3 ", "agent-session-grep 1.2.3\t",
                             "agent-session-grep 1.2.3\n\n", "agent-session-grep 1.2.3\r",
                             "agent-session-grep 1.2.3\r\n\r\n", "agent-session-grep 1.2.3\x00",
                             "agent-session-grep v1.2.3", "agent-session-grep 1.2.3+extra"):
                with self.subTest(workflow=name, reported=reported), self.assertRaises(ValueError):
                    validate(reported, "1.2.3")

    def test_binary_version_entry_rejects_nonzero_exit_even_with_correct_stdout(self):
        for name in ("release.yml", "release-verify.yml"):
            control, source = load_step(name, "build", "verify_binary")
            env = {"TARGET": "test-target", "BINARY": "agent-session-grep", "VERSION": "1.2.3"}
            with self.subTest(workflow=name), tempfile.TemporaryDirectory() as tmp:
                with contextlib.chdir(tmp):
                    binary = Path("target/test-target/release/agent-session-grep")
                    binary.parent.mkdir(parents=True)
                    binary.write_bytes(b"synthetic executable seam")
                    resolved = str(binary.resolve(strict=True))
                    error = subprocess.CalledProcessError(7, [resolved, "--version"],
                                                         output="agent-session-grep 1.2.3\n")
                    with patch("subprocess.check_output", side_effect=error) as execute:
                        with self.assertRaises(subprocess.CalledProcessError) as caught:
                            run_main(control, source, env)
                    self.assertEqual(caught.exception.returncode, 7)
                    self.assertEqual(caught.exception.output, "agent-session-grep 1.2.3\n")
                    execute.assert_called_once_with([resolved, "--version"], text=True)

    def test_binary_version_entry_rejects_missing_binary_before_execution(self):
        for name in ("release.yml", "release-verify.yml"):
            control, source = load_step(name, "build", "verify_binary")
            env = {"TARGET": "test-target", "BINARY": "missing", "VERSION": "1.2.3"}
            with self.subTest(workflow=name), tempfile.TemporaryDirectory() as tmp:
                with contextlib.chdir(tmp), patch("subprocess.check_output") as execute:
                    with self.assertRaises(FileNotFoundError):
                        run_main(control, source, env)
                    execute.assert_not_called()

    def test_version_rejects_noncanonical_and_hostile_components(self):
        for name in ("release.yml", "release-verify.yml"):
            control, _ = load_step(name, "prepare", "version")
            validate = control["validate_version"]
            for version in ("0.1.0", "1.2.3", "1.2.3-rc.1+build.7"):
                self.assertEqual(validate(version), version)
            for version in (None, "", "v1.2.3", "01.2.3", "1.2.3-01", "../1.2.3",
                            "1.2.3;echo injected", "1.2.3\n", "1.2.3$(echo injected)"):
                with self.subTest(workflow=name, version=version), self.assertRaises(ValueError):
                    validate(version)

    def test_workspace_version_step_reads_b_epoch_and_rejects_tag_drift(self):
        for name in ("release.yml", "release-verify.yml"):
            control, source = load_step(name, "prepare", "version")
            with self.subTest(workflow=name), release_bundle() as bundle:
                output = bundle.base / "output"
                env = {"SOURCE_COMMIT": bundle.source_commit, "REQUESTED_TAG": bundle.tag,
                       "GITHUB_OUTPUT": str(output), "GITHUB_SHA": oid("caller-a")}
                with contextlib.chdir(bundle.workspace), patch("subprocess.check_output", return_value=str(bundle.epoch) + "\n") as git:
                    run_main(control, source, env)
                    git.assert_called_once_with(["git", "show", "-s", "--format=%ct", bundle.source_commit], text=True)
                outputs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
                self.assertEqual(outputs, {"tag": bundle.tag, "version": bundle.version,
                                           "source_date_epoch": str(bundle.epoch), "cargo_lock_sha256": bundle.lock_hash})
                env["REQUESTED_TAG"] = "v9.9.9"
                with contextlib.chdir(bundle.workspace), patch("subprocess.check_output") as git, self.assertRaises(ValueError):
                    run_main(control, source, env)
                git.assert_not_called()


class ReleaseInputMaterializationTests(unittest.TestCase):
    def test_all_six_entries_restore_only_exact_source_blobs_and_keep_head_assertion(self):
        expected_ast = ast.dump(next(node for node in ast.parse(load_step("ci.yml", "test", "assert_source")[1]).body
                                     if isinstance(node, ast.FunctionDef) and node.name == "assert_source"))
        materializers = set()
        with git_release_bundle() as bundle:
            sentinel = bundle.workspace / "unrelated-golden.fixture"
            sentinel.write_bytes(b"fixture\r\n\xff\n")
            config = (bundle.workspace / ".git/config").read_bytes()
            for name in ("release.yml", "release-verify.yml"):
                for job_name in ("prepare", "build", "assemble"):
                    control, source = load_step(name, job_name, "assert_source")
                    with self.subTest(workflow=name, job=job_name):
                        self.assertEqual(control["RELEASE_INPUTS"], RELEASE_INPUTS)
                        functions = {node.name: ast.dump(node) for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
                        self.assertEqual(functions["assert_source"], expected_ast)
                        materializers.add(functions["materialize_release_inputs"])
                        checkout_release_inputs(bundle, bundle.workspace, crlf=True)
                        self.assertEqual({item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS},
                                         {item: data.replace(b"\n", b"\r\n") for item, data in bundle.git_inputs.items()})
                        real_git = subprocess.check_output
                        env = {**bundle.git_environment, "SOURCE_COMMIT": bundle.source_commit}
                        with contextlib.chdir(bundle.workspace), patch("subprocess.check_output", wraps=real_git) as git:
                            run_main(control, source, env)
                        self.assertEqual(git.call_args_list[0].args[0], ["git", "rev-parse", "HEAD"])
                        self.assertEqual(git.call_args_list[1].args[0],
                                         ["git", "ls-tree", "-z", "--full-tree", bundle.source_commit, "--", *RELEASE_INPUTS])
                        self.assertEqual([call.args[0] for call in git.call_args_list[2:]],
                                         [["git", "cat-file", "blob", bundle.git_objects[item].decode()] for item in RELEASE_INPUTS])
                        self.assertTrue(all(not call.kwargs.get("text") for call in git.call_args_list[2:]))
                        self.assertEqual({item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS}, bundle.git_inputs)
                        self.assertEqual(sentinel.read_bytes(), b"fixture\r\n\xff\n")
                        self.assertEqual((bundle.workspace / ".git/config").read_bytes(), config)
                        before = {item: (bundle.workspace / item).stat().st_mtime_ns for item in RELEASE_INPUTS}
                        with contextlib.chdir(bundle.workspace):
                            run_main(control, source, env)
                        self.assertEqual(before, {item: (bundle.workspace / item).stat().st_mtime_ns for item in RELEASE_INPUTS})
        self.assertEqual(len(materializers), 1, "all six byte-boundary controllers must stay identical")

    def test_mixed_eol_real_producer_rejects_before_and_accepts_after_materialization(self):
        for workflow in ("release.yml", "release-verify.yml"):
            for variant in ("all-inputs", "documents-only"):
                with self.subTest(workflow=workflow, variant=variant), git_release_bundle() as bundle:
                    windows = bundle.base / "windows-checkout"
                    windows.mkdir()
                    checkout_release_inputs(bundle, bundle.workspace, crlf=False)
                    checkout_release_inputs(bundle, windows, crlf=True)
                    self.assertEqual((windows / "Cargo.lock").read_bytes(), bundle.git_inputs["Cargo.lock"].replace(b"\n", b"\r\n"))
                    if variant == "documents-only":
                        for filename in ("Cargo.toml", "Cargo.lock"):
                            (windows / filename).write_bytes(bundle.git_inputs[filename])
                    package_checkout_variants(bundle, windows)
                    message = "input or unsigned provenance" if variant == "all-inputs" else "documents differ"
                    for name, ident, validator in artifact_controls():
                        with self.subTest(consumer=name, job=ident), self.assertRaisesRegex(ValueError, message):
                            bundle.validate(validator)
                    control, source = load_step(workflow, "build", "assert_source")
                    env = {**bundle.git_environment, "SOURCE_COMMIT": bundle.source_commit,
                           "GIT_DIR": str(bundle.workspace / ".git"), "GIT_WORK_TREE": str(windows)}
                    with contextlib.chdir(windows):
                        run_main(control, source, env)
                    self.assertEqual({item: (windows / item).read_bytes() for item in RELEASE_INPUTS}, bundle.git_inputs)
                    package_checkout_variants(bundle, windows)
                    for name, ident, validator in artifact_controls():
                        with self.subTest(consumer=name, job=ident):
                            bundle.validate(validator)

    def test_blob_materialization_is_not_a_blanket_newline_or_text_conversion(self):
        original = b"source CRLF\r\nand opaque byte \xff\n"
        with git_release_bundle({"README.md": original}) as bundle:
            control, _ = load_step("release.yml", "prepare", "assert_source")
            (bundle.workspace / "README.md").write_bytes(original.replace(b"\r\n", b"\n"))
            with contextlib.chdir(bundle.workspace):
                control["materialize_release_inputs"](bundle.source_commit)
            self.assertEqual((bundle.workspace / "README.md").read_bytes(), original)

    def test_nonregular_git_entries_and_incomplete_blob_reads_never_write_inputs(self):
        control, _ = load_step("release.yml", "prepare", "assert_source")
        with git_release_bundle() as bundle:
            for filename, content in bundle.git_inputs.items():
                (bundle.workspace / filename).write_bytes(content.replace(b"\n", b"\r\n"))
            before = {item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS}
            real_git = subprocess.check_output
            for kind in ("symlink", "gitlink", "empty", "missing", "duplicate", "truncated", "blob-error"):
                blob_calls = 0
                def git(argv, **kwargs):
                    nonlocal blob_calls
                    data = real_git(argv, **kwargs)
                    if argv[1] == "ls-tree":
                        if kind == "empty":
                            return b""
                        if kind == "symlink":
                            return data.replace(b"100644 blob", b"120000 blob", 1)
                        if kind == "gitlink":
                            return data.replace(b"100644 blob", b"160000 commit", 1)
                        if kind == "missing":
                            return b"\0".join(data.split(b"\0")[1:])
                        if kind == "duplicate":
                            return data + data.split(b"\0")[0] + b"\0"
                        if kind == "truncated":
                            return data[:-1]
                    if argv[1] == "cat-file":
                        blob_calls += 1
                        if kind == "blob-error" and blob_calls == 2:
                            raise subprocess.CalledProcessError(1, argv)
                    return data
                with self.subTest(kind=kind), contextlib.chdir(bundle.workspace), \
                        patch("subprocess.check_output", side_effect=git), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    control["materialize_release_inputs"](bundle.source_commit)
                self.assertEqual(before, {item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS})

    def test_local_nonregular_and_linked_inputs_are_rejected_without_following(self):
        control, _ = load_step("release.yml", "prepare", "assert_source")
        with git_release_bundle() as bundle:
            for filename, content in bundle.git_inputs.items():
                (bundle.workspace / filename).write_bytes(content.replace(b"\n", b"\r\n"))
            before = {item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS}
            real_lstat = Path.lstat
            for kind in (stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO):
                def lstat(path, *args, **kwargs):
                    if path.name == "README.md":
                        return os.stat_result((kind | 0o644, 1, 1, 1, 0, 0, 0, 0, 0, 0))
                    return real_lstat(path, *args, **kwargs)
                with self.subTest(kind=kind), contextlib.chdir(bundle.workspace), \
                        patch.object(Path, "lstat", lstat), self.assertRaises(ValueError):
                    control["materialize_release_inputs"](bundle.source_commit)
                self.assertEqual(before, {item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS})
            alias = bundle.base / "outside-input-alias"
            os.link(bundle.workspace / "README.md", alias)
            with contextlib.chdir(bundle.workspace), self.assertRaises(ValueError):
                control["materialize_release_inputs"](bundle.source_commit)
            self.assertEqual(alias.read_bytes(), before["README.md"])
            self.assertEqual(before, {item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS})

    def test_wrong_or_invalid_source_and_missing_files_do_not_trigger_recovery(self):
        with git_release_bundle() as bundle:
            for workflow in ("release.yml", "release-verify.yml"):
                for job_name in ("prepare", "build", "assemble"):
                    control, source = load_step(workflow, job_name, "assert_source")
                    env = {**bundle.git_environment, "SOURCE_COMMIT": oid("wrong-source")}
                    with self.subTest(workflow=workflow, job=job_name), contextlib.chdir(bundle.workspace), \
                            patch.dict(control, {"materialize_release_inputs": unittest.mock.Mock()}):
                        materialize = control["materialize_release_inputs"]
                        with self.assertRaises(ValueError):
                            run_main(control, source, env)
                        materialize.assert_not_called()
            control, _ = load_step("release.yml", "prepare", "assert_source")
            for value in (None, "", "0" * 40, "HEAD", oid("tag-b") + "\n"):
                with self.subTest(source=value), patch("subprocess.check_output") as git, self.assertRaises(ValueError):
                    control["materialize_release_inputs"](value)
                git.assert_not_called()
            missing = bundle.workspace / "NOTICE"
            missing.unlink()
            before = {item: (bundle.workspace / item).read_bytes() for item in RELEASE_INPUTS if item != "NOTICE"}
            with contextlib.chdir(bundle.workspace), self.assertRaises((ValueError, FileNotFoundError)):
                control["materialize_release_inputs"](bundle.source_commit)
            self.assertFalse(missing.exists(), "missing fixed inputs must not be recreated as a fallback")
            self.assertEqual(before, {item: (bundle.workspace / item).read_bytes() for item in before})


class ArtifactValidationTests(unittest.TestCase):
    @staticmethod
    def rewrite_archive(bundle, target, change):
        archive = bundle.archives[target]
        if target == TARGETS[0]:
            with zipfile.ZipFile(archive) as packed:
                entries = [(info, packed.read(info)) for info in packed.infolist()]
            change(entries)
            with zipfile.ZipFile(archive, "w") as packed:
                for info, content in entries:
                    packed.writestr(info, content)
        else:
            with tarfile.open(archive, "r:gz") as packed:
                entries = [(info, packed.extractfile(info).read()) for info in packed.getmembers()]
            change(entries)
            with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=bundle.epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as packed:
                    for info, content in entries:
                        packed.addfile(info, io.BytesIO(content))

    @staticmethod
    def refresh_archive_metadata(bundle, target):
        archive = bundle.archives[target]
        bundle.change_manifest(["archive", "sha256"], BUILD_MANIFEST.sha256_file(archive), target)
        bundle.change_manifest(["archive", "size_bytes"], archive.stat().st_size, target)

    def test_actual_archive_headers_must_match_the_prepared_epoch(self):
        for name, ident, control in artifact_controls():
            for target, field in ((TARGETS[0], "member"), (TARGETS[1], "member"), (TARGETS[1], "gzip")):
                with self.subTest(workflow=name, job=ident, target=target, field=field), release_bundle() as bundle:
                    if field == "gzip":
                        archive = bundle.archives[target]
                        data = bytearray(archive.read_bytes())
                        data[4:8] = (bundle.epoch + 2).to_bytes(4, "little")
                        archive.write_bytes(data)
                    else:
                        def change(entries):
                            info = entries[0][0]
                            if target == TARGETS[0]:
                                info.date_time = info.date_time[:5] + (info.date_time[5] + 2,)
                            else:
                                info.mtime = bundle.epoch + 2
                        self.rewrite_archive(bundle, target, change)
                    # Refresh all outer digests: only the physical header/declared
                    # epoch mismatch, not a stale checksum, may reject this bundle.
                    self.refresh_archive_metadata(bundle, target)
                    with self.assertRaises(ValueError):
                        bundle.validate(control)

    def test_real_archives_accept_zip_epoch_clamping_and_two_second_precision(self):
        for name, ident, control in artifact_controls():
            for epoch in (0, 315_532_799, 1_700_000_001):
                with self.subTest(workflow=name, job=ident, epoch=epoch), \
                        patch.object(ReleaseBundle, "epoch", epoch), release_bundle() as bundle:
                    bundle.validate(control)

    def test_actual_archive_members_cannot_hide_behind_fresh_outer_hashes(self):
        for name, ident, control in artifact_controls():
            for target in TARGETS[:2]:
                for mutation in ("missing", "extra", "duplicate", "path", "link", "mode", "size", "content"):
                    with self.subTest(workflow=name, job=ident, target=target, mutation=mutation), release_bundle() as bundle:
                        def change(entries):
                            info, content = entries[0]
                            if mutation == "missing":
                                entries.pop()
                            elif mutation == "extra":
                                extra = copy.deepcopy(info)
                                if target == TARGETS[0]:
                                    extra.filename += ".extra"
                                else:
                                    extra.name += ".extra"
                                entries.append((extra, content))
                            elif mutation == "duplicate":
                                entries[1] = (copy.deepcopy(info), content)
                            elif mutation == "path":
                                if target == TARGETS[0]:
                                    info.filename = "../outside"
                                else:
                                    info.name = "../outside"
                            elif mutation == "link":
                                if target == TARGETS[0]:
                                    info.external_attr = 0o120777 << 16
                                else:
                                    info.type, info.linkname, info.size = tarfile.SYMTYPE, "../outside", 0
                                    entries[0] = (info, b"")
                            elif mutation == "mode":
                                if target == TARGETS[0]:
                                    info.external_attr = 0o644 << 16
                                else:
                                    info.mode = 0o644
                            else:
                                content = content + b"x" if mutation == "size" else b"X" + content[1:]
                                if target != TARGETS[0]:
                                    info.size = len(content)
                                entries[0] = (info, content)
                        warning = self.assertWarns(UserWarning) if target == TARGETS[0] and mutation == "duplicate" else contextlib.nullcontext()
                        with warning:
                            self.rewrite_archive(bundle, target, change)
                        self.refresh_archive_metadata(bundle, target)
                        with self.assertRaises(ValueError):
                            bundle.validate(control)

    def test_real_producer_four_target_bundle_is_accepted_by_every_consumer(self):
        for name, ident, control in artifact_controls():
            with self.subTest(workflow=name, job=ident), release_bundle() as bundle:
                self.assertEqual(len(list(bundle.dist.iterdir())), 11)
                bundle.validate(control)

    def test_caller_a_or_wrong_version_epoch_lock_hash_cannot_replace_b(self):
        for name, ident, control in artifact_controls():
            for overrides in ({"source_commit": oid("caller-a")}, {"source_commit": "0" * 40},
                              {"tag": "v9.9.9"}, {"version": "9.9.9"},
                              {"source_date_epoch": ReleaseBundle.epoch + 1}, {"cargo_lock_sha256": "f" * 64}):
                with self.subTest(workflow=name, job=ident, overrides=overrides), release_bundle() as bundle:
                    with self.assertRaises(ValueError):
                        bundle.validate(control, **overrides)

    def test_manifest_provenance_target_and_archive_metadata_cannot_drift(self):
        mutations = ((["unexpected"], "unvalidated"), (["archive", "unexpected"], "unvalidated"),
                     (["inputs", "unexpected"], "unvalidated"), (["provenance", "unexpected"], "unvalidated"),
                     (["schema"], "unexpected/v1"), (["release", "tag"], "v9.9.9"),
                     (["release", "version"], "9.9.9"), (["release", "source_commit"], oid("caller-a")),
                     (["release", "source_date_epoch"], ReleaseBundle.epoch + 1),
                     (["release", "target"], TARGETS[1]), (["release", "unsigned"], False),
                     (["release", "unsigned"], "true"), (["provenance", "cryptographic_attestation"], True),
                     (["provenance", "kind"], "signed"), (["inputs", "cargo_lock_sha256"], "f" * 64),
                     (["archive", "sha256"], "f" * 64), (["archive", "size_bytes"], 0),
                     (["archive", "filename"], "../outside.zip"), (["archive", "root"], "../outside"))
        for name, ident, control in artifact_controls():
            for field, value in mutations:
                with self.subTest(workflow=name, job=ident, field=field, value=value), release_bundle() as bundle:
                    bundle.change_manifest(field, value)
                    with self.assertRaises(ValueError):
                        bundle.validate(control)

    def test_missing_extra_or_duplicate_target_artifacts_fail(self):
        for name, ident, control in artifact_controls():
            for missing in ("archive", "manifest", "SHA256SUMS", "THIRD-PARTY-DEPENDENCIES.json"):
                with self.subTest(workflow=name, job=ident, missing=missing), release_bundle() as bundle:
                    path = (bundle.archives[TARGETS[0]] if missing == "archive" else
                            bundle.manifests[TARGETS[0]] if missing == "manifest" else bundle.dist / missing)
                    path.unlink()
                    with self.assertRaises(ValueError):
                        bundle.validate(control)
            for extra in ("unexpected.txt", "extra-target.manifest.json"):
                with self.subTest(workflow=name, job=ident, extra=extra), release_bundle() as bundle:
                    (bundle.dist / extra).write_text("synthetic", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        bundle.validate(control)
            with self.subTest(workflow=name, job=ident, extra="directory"), release_bundle() as bundle:
                (bundle.dist / "unexpected-directory").mkdir()
                with self.assertRaises(ValueError):
                    bundle.validate(control)

    def test_archive_and_member_hash_tampering_fail_even_with_fresh_outer_checksums(self):
        for name, ident, control in artifact_controls():
            for target in (TARGETS[0], TARGETS[1]):
                with self.subTest(workflow=name, job=ident, target=target), release_bundle() as bundle:
                    archive = bundle.archives[target]
                    archive.write_bytes(archive.read_bytes() + b"synthetic corruption")
                    bundle.refresh_checksums()
                    with self.assertRaises(ValueError):
                        bundle.validate(control)
            with self.subTest(workflow=name, job=ident, kind="member"), release_bundle() as bundle:
                bundle.change_manifest(["archive", "files", 0, "sha256"], "f" * 64)
                with self.assertRaises(ValueError):
                    bundle.validate(control)
            with self.subTest(workflow=name, job=ident, kind="inventory"), release_bundle() as bundle:
                inventory = bundle.dist / "THIRD-PARTY-DEPENDENCIES.json"
                data = json.loads(inventory.read_text(encoding="utf-8"))
                data["release_version"] = "9.9.9"
                inventory.write_text(json.dumps(data), encoding="utf-8")
                bundle.refresh_checksums()
                with self.assertRaises(ValueError):
                    bundle.validate(control)

    def test_checksums_require_exact_unique_coverage_and_valid_hashes(self):
        for name, ident, control in artifact_controls():
            for mutation in ("missing", "duplicate", "wrong-hash", "traversal", "malformed"):
                with self.subTest(workflow=name, job=ident, mutation=mutation), release_bundle() as bundle:
                    path = bundle.dist / "SHA256SUMS"
                    lines = path.read_text(encoding="utf-8").splitlines()
                    if mutation == "missing":
                        lines.pop()
                    elif mutation == "duplicate":
                        lines.append(lines[0])
                    elif mutation == "wrong-hash":
                        lines[0] = "f" * 64 + lines[0][64:]
                    elif mutation == "traversal":
                        lines[0] = lines[0][:66] + "../outside"
                    else:
                        lines[0] = "not a checksum"
                    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        bundle.validate(control)

    def test_malformed_manifest_never_counts_as_a_valid_target(self):
        for name, ident, control in artifact_controls():
            for data in (b"{", b"null", b"[]", b"\xff"):
                with self.subTest(workflow=name, job=ident, data=data), release_bundle() as bundle:
                    bundle.manifests[TARGETS[0]].write_bytes(data)
                    bundle.refresh_checksums()
                    with self.assertRaises(ValueError):
                        bundle.validate(control)


class RequiredStepEvidenceTests(unittest.TestCase):
    def test_control_required_step_policy_matches_independent_inventory(self):
        leaves = [f"{kind} ({runner})" for kind in ("test", "installer smoke")
                  for runner in ("ubuntu-latest", "windows-latest", "macos-latest")]
        leaves += ["Cargo dependency audit", *SPECIAL_STEPS]
        leaves += [kind + " " + target for kind in ("build", "verify") for target in TARGETS]
        for workflow, ident, control in gate_controls():
            for leaf in leaves:
                with self.subTest(workflow=workflow, job=ident, leaf=leaf):
                    self.assertCountEqual(control["required_step_names"](leaf), fixture_step_names(leaf))

    def test_green_jobs_cannot_hide_skipped_missing_duplicate_or_failed_commands(self):
        leaves = ["test (ubuntu-latest)", "installer smoke (windows-latest)",
                  "installer smoke (ubuntu-latest)", "installer smoke (macos-latest)",
                  "Cargo dependency audit", *SPECIAL_STEPS, "build " + TARGETS[0], "verify " + TARGETS[3]]
        for workflow, ident, control in gate_controls():
            for leaf in leaves:
                good = job_record(leaf)
                for index, required in enumerate(fixture_step_names(leaf)):
                    for state in ("failure", "skipped", "cancelled", "neutral", None):
                        changed = copy.deepcopy(good)
                        changed["steps"][index]["conclusion"] = state
                        with self.subTest(workflow=workflow, job=ident, leaf=leaf, step=required, state=state), self.assertRaises(ValueError):
                            control["require_jobs"]([changed], [leaf], 501, 2, oid("caller-a"))
                    missing = copy.deepcopy(good)
                    missing["steps"].pop(index)
                    duplicate = copy.deepcopy(good)
                    duplicate["steps"].append(step_record(required, len(good["steps"]) + 1))
                    pending = copy.deepcopy(good)
                    pending["steps"][index]["status"] = "in_progress"
                    for changed in (missing, duplicate, pending):
                        with self.subTest(workflow=workflow, job=ident, leaf=leaf, step=required), self.assertRaises(ValueError):
                            control["require_jobs"]([changed], [leaf], 501, 2, oid("caller-a"))
                for steps_value in (None, [], {}, [None], [step_record("unexpected", True)]):
                    changed = {**good, "steps": steps_value}
                    with self.subTest(workflow=workflow, job=ident, leaf=leaf, malformed=steps_value), self.assertRaises(ValueError):
                        control["require_jobs"]([changed], [leaf], 501, 2, oid("caller-a"))

    def test_opposite_os_branches_and_post_actions_may_be_skipped(self):
        for workflow, ident, control in gate_controls():
            for runner in ("windows-latest", "ubuntu-latest", "macos-latest"):
                leaf = f"installer smoke ({runner})"
                good = job_record(leaf)
                opposite = "unix" if runner == "windows-latest" else "windows"
                optional = (f"Install into a workspace-local prefix ({opposite})",
                            f"Invoke both installed commands ({opposite})", f"Surface smoke ({opposite})",
                            f"Uninstall twice ({opposite})", "Post actions/checkout", "Post Cache cargo registry and target")
                good["steps"].extend(step_record(name, index, "skipped") for index, name in enumerate(optional, 100))
                with self.subTest(workflow=workflow, job=ident, runner=runner):
                    control["require_jobs"]([good], [leaf], 501, 2, oid("caller-a"))

    def test_unexpanded_matrix_placeholder_never_counts_as_four_targets(self):
        for workflow, ident, control in gate_controls():
            for kind in ("build", "verify"):
                expected = [kind + " " + target for target in TARGETS]
                placeholder = job_record(kind + " ${{ matrix.target }}", 20)
                placeholder["conclusion"] = "skipped"
                for records in ([placeholder], [job_record(name, index) for index, name in enumerate(expected[:3], 1)] + [placeholder]):
                    with self.subTest(workflow=workflow, job=ident, kind=kind), self.assertRaises(ValueError):
                        control["require_jobs"](records, expected, 501, 2, oid("caller-a"))

    def test_gate_entrypoints_enforce_fixed_job_and_step_inventories(self):
        endpoint = "repos/sample/project/actions/runs/501/attempts/2/jobs?per_page=100&page=1"
        for name in ("ci.yml", "release.yml", "release-verify.yml"):
            control, source = load_step(name, "gate", "gate")
            expected = expected_gate_leaves(name)
            good = [job_record(leaf, index) for index, leaf in enumerate(expected, 1)]
            env = gate_environment(name, oid("caller-a"))
            env["SOURCE_COMMIT"] = oid("tag-b")
            with gate_event("workflow_dispatch", {}) as event_env:
                env.update(event_env)
                api = FakeAPI({endpoint: {"total_count": len(good), "jobs": good}})
                with self.subTest(workflow=name), patch.dict(control, {"api_get": api}):
                    run_main(control, source, env)
                for index, leaf in enumerate(expected):
                    bad = copy.deepcopy(good)
                    bad[index]["steps"][0]["conclusion"] = "skipped"
                    api = FakeAPI({endpoint: {"total_count": len(bad), "jobs": bad}})
                    with self.subTest(workflow=name, leaf=leaf), patch.dict(control, {"api_get": api}), self.assertRaises(ValueError):
                        run_main(control, source, env)


class ReleaseAbsenceTests(unittest.TestCase):
    def setUp(self):
        self.control, _ = load_step("release.yml", "publish", "publish")
        self.repo = "sample/project"
        self.tag = "v1.2.3"
        self.tag_path = "repos/sample/project/releases/tags/" + self.tag
        self.page = "repos/sample/project/releases?per_page=100&page="

    def require_absent(self, responses):
        api = FakeAPI(responses)
        self.control["require_absent_release"](api, self.repo, self.tag)
        return api

    def test_confirmed_absence_requires_visibility_all_pages_and_fresh_lookup(self):
        responses = absence_responses()
        responses[self.page + "1"] = [release_record()]
        responses[self.page + "2"] = [release_record("v0.9.1", 8, draft=True)]
        responses[self.page + "3"] = []
        api = self.require_absent(responses)
        self.assertEqual([path for path, _ in api.calls], ["repos/sample/project", self.tag_path,
                         self.page + "1", self.page + "2", self.page + "3", self.tag_path])
        self.assertTrue(all(allowed for path, allowed in api.calls if path == self.tag_path))

    def test_existing_published_or_draft_release_with_or_without_assets_rejects(self):
        for draft in (False, True):
            for assets in ([], [{"id": 91, "name": "existing.zip"}]):
                existing = release_record(self.tag, draft=draft, assets=assets)
                responses = absence_responses()
                responses[self.tag_path] = existing
                with self.subTest(draft=draft, assets=bool(assets), source="tag"), self.assertRaises(ValueError):
                    self.require_absent(responses)
                responses[self.tag_path] = None
                responses[self.page + "1"] = [release_record()]
                responses[self.page + "2"] = [existing]
                with self.subTest(draft=draft, assets=bool(assets), source="page2"), self.assertRaises(ValueError):
                    self.require_absent(responses)

    def test_missing_push_visibility_wrong_identity_or_auth_failure_is_not_absence(self):
        for info in (None, {}, {"id": 123, "full_name": self.repo, "permissions": {"push": False}},
                     {"id": 123, "full_name": self.repo, "permissions": {"push": 1}},
                     {"id": 123, "full_name": "other/project", "permissions": {"push": True}},
                     {"id": True, "full_name": self.repo, "permissions": {"push": True}}):
            responses = absence_responses()
            responses["repos/sample/project"] = info
            with self.subTest(info=info), self.assertRaises(ValueError):
                self.require_absent(responses)
        for endpoint in ("repos/sample/project", self.tag_path, self.page + "1"):
            for failure in (URLError("synthetic unavailable"),
                            HTTPError("https://api.github.com/synthetic", 403, "denied", {}, None),
                            HTTPError("https://api.github.com/synthetic", 500, "failure", {}, None)):
                responses = absence_responses()
                responses[endpoint] = failure
                with self.subTest(endpoint=endpoint, failure=type(failure).__name__), self.assertRaises((ValueError, URLError)):
                    self.require_absent(responses)

    def test_malformed_duplicate_or_unfinished_release_and_asset_pages_reject(self):
        malformed = (None, {}, [None], [{"id": 1}], [release_record(ident=True)],
                     [{**release_record(), "draft": "false"}], [{**release_record(), "assets": None}],
                     [release_record(), release_record()],
                     [release_record(assets=[{"id": 1, "name": "one"}, {"id": 1, "name": "two"}])],
                     [release_record(assets=[{"id": 1, "name": ""}])], [release_record(assets=[None])])
        for page in malformed:
            responses = absence_responses()
            responses[self.page + "1"] = page
            with self.subTest(page=page), self.assertRaises(ValueError):
                self.require_absent(responses)
        for second in ([release_record()], URLError("synthetic truncated inventory"),
                       HTTPError("https://api.github.com/synthetic", 403, "denied", {}, None),
                       HTTPError("https://api.github.com/synthetic", 503, "failure", {}, None)):
            responses = absence_responses()
            responses[self.page + "1"] = [release_record()]
            responses[self.page + "2"] = second
            with self.subTest(second=second), self.assertRaises((ValueError, URLError)):
                self.require_absent(responses)

    def test_release_appearing_during_preflight_is_rejected(self):
        api = FakeAPI(absence_responses())
        lookups = 0
        def changed(path, allow_not_found=False):
            nonlocal lookups
            if path.removeprefix("/") == self.tag_path:
                lookups += 1
                if lookups == 2:
                    return release_record(self.tag, draft=True)
            return api(path, allow_not_found)
        with self.assertRaises(ValueError):
            self.control["require_absent_release"](changed, self.repo, self.tag)
        self.assertEqual(lookups, 2)


class AssemblyControlTests(unittest.TestCase):
    def test_exact_four_download_directories_assemble_without_overwriting(self):
        for name in ("release.yml", "release-verify.yml"):
            control, _ = load_step(name, "assemble", "assemble_artifacts")
            validator, _ = load_step(name, "assemble", "validate_artifacts")
            with self.subTest(workflow=name), release_bundle() as bundle:
                prefix = "release-target-" + bundle.source_commit + "-"
                artifacts, inputs, output = make_downloads(bundle, prefix)
                control["assemble_artifacts"](artifacts, inputs, output, prefix, bundle.tag)
                self.assertEqual(len(list(output.iterdir())), 10)
                BUILD_MANIFEST.write_checksums(output, output / "SHA256SUMS")
                bundle.validate(validator, root=output)

    def test_missing_extra_and_duplicate_target_downloads_reject_before_copy(self):
        for name in ("release.yml", "release-verify.yml"):
            control, _ = load_step(name, "assemble", "assemble_artifacts")
            for mutation in ("missing", "extra", "duplicate-target", "extra-member", "bad-checksum", "missing-inventory"):
                with self.subTest(workflow=name, mutation=mutation), release_bundle() as bundle:
                    prefix = "release-target-" + bundle.source_commit + "-"
                    targets = TARGETS[:-1] if mutation == "missing" else TARGETS
                    artifacts, inputs, output = make_downloads(bundle, prefix, targets)
                    if mutation == "extra":
                        (artifacts / (prefix + "unexpected-target")).mkdir()
                    elif mutation == "duplicate-target":
                        folder = artifacts / (prefix + TARGETS[-1])
                        for path in folder.iterdir():
                            path.unlink()
                        for path in (artifacts / (prefix + TARGETS[0])).iterdir():
                            (folder / path.name).write_bytes(path.read_bytes())
                    elif mutation == "extra-member":
                        (artifacts / (prefix + TARGETS[0]) / "unexpected").write_text("synthetic", encoding="utf-8")
                    elif mutation == "bad-checksum":
                        (artifacts / (prefix + TARGETS[0]) / "SHA256SUMS").write_text("not a checksum", encoding="utf-8")
                    elif mutation == "missing-inventory":
                        (inputs / "THIRD-PARTY-DEPENDENCIES.csv").unlink()
                    with self.assertRaises(ValueError):
                        control["assemble_artifacts"](artifacts, inputs, output, prefix, bundle.tag)
                    self.assertFalse(output.exists(), "invalid inventories must fail before output creation")

    def test_existing_output_is_preserved_not_merged_or_replaced(self):
        for name in ("release.yml", "release-verify.yml"):
            control, _ = load_step(name, "assemble", "assemble_artifacts")
            with self.subTest(workflow=name), release_bundle() as bundle:
                prefix = "release-target-" + bundle.source_commit + "-"
                artifacts, inputs, output = make_downloads(bundle, prefix)
                output.mkdir()
                sentinel = output / "preserve-existing"
                sentinel.write_bytes(b"existing bytes")
                with self.assertRaises((ValueError, FileExistsError)):
                    control["assemble_artifacts"](artifacts, inputs, output, prefix, bundle.tag)
                self.assertEqual(list(output.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_bytes(), b"existing bytes")


class PublicationControlTests(unittest.TestCase):
    def setUp(self):
        self.control, self.source = load_step("release.yml", "publish", "publish")

    def invoke(self, bundle, api, env):
        with contextlib.chdir(bundle.base), patch.dict(self.control, {"api_get": api}):
            run_main(self.control, self.source, env)

    def responses(self, bundle):
        responses = absence_responses(bundle.tag)
        responses[f"repos/sample/project/git/ref/tags/{bundle.tag}"] = tag_response(bundle.tag, bundle.source_commit)
        return responses

    def test_publish_control_uses_only_one_verified_create_with_literal_arguments(self):
        with release_bundle() as bundle:
            api = FakeAPI(self.responses(bundle))
            with patch("subprocess.run") as command:
                self.invoke(bundle, api, publish_environment(bundle))
            command.assert_called_once()
            argv = command.call_args.args[0]
            self.assertEqual(argv[:4], ["gh", "release", "create", bundle.tag])
            self.assertIn("--verify-tag", argv)
            self.assertEqual(argv[argv.index("--repo") + 1], "sample/project")
            self.assertTrue(command.call_args.kwargs["check"])
            self.assertNotIn("shell", command.call_args.kwargs)
            self.assertNotIn("--clobber", argv)
            self.assertEqual(len([value for value in argv if value.startswith("dist")]), 11)

    def test_missing_moved_or_reannotated_remote_tag_never_creates_release(self):
        for mutation in ("missing", "moved-commit", "moved-object-same-commit", "prefix-ref"):
            with self.subTest(mutation=mutation), release_bundle() as bundle:
                responses, env = self.responses(bundle), publish_environment(bundle)
                ref_path = f"repos/sample/project/git/ref/tags/{bundle.tag}"
                if mutation == "missing":
                    responses[ref_path] = None
                elif mutation == "moved-commit":
                    responses[ref_path] = tag_response(bundle.tag, oid("moved-commit"))
                elif mutation == "prefix-ref":
                    responses[ref_path] = tag_response(bundle.tag + "-other", bundle.source_commit)
                else:
                    env["TAG_OBJECT"] = oid("original-annotation")
                    moved = oid("replacement-annotation")
                    responses[ref_path] = tag_response(bundle.tag, moved, "tag")
                    responses[f"repos/sample/project/git/tags/{moved}"] = {
                        "sha": moved, "object": {"type": "commit", "sha": bundle.source_commit}}
                with patch("subprocess.run") as command, self.assertRaises(ValueError):
                    self.invoke(bundle, FakeAPI(responses), env)
                command.assert_not_called()

    def test_existing_release_assets_or_invisible_repository_block_all_writes(self):
        for mutation in ("published", "draft-page", "no-permission", "wrong-repository-id", "api-unavailable"):
            with self.subTest(mutation=mutation), release_bundle() as bundle:
                responses, env = self.responses(bundle), publish_environment(bundle)
                if mutation == "published":
                    responses[f"repos/sample/project/releases/tags/{bundle.tag}"] = release_record(
                        bundle.tag, assets=[{"id": 91, "name": "preserve-existing.zip"}])
                elif mutation == "draft-page":
                    responses["repos/sample/project/releases?per_page=100&page=1"] = [release_record(bundle.tag, draft=True)]
                elif mutation == "no-permission":
                    responses["repos/sample/project"]["permissions"]["push"] = False
                elif mutation == "wrong-repository-id":
                    env["REPOSITORY_ID"] = "456"
                else:
                    responses["repos/sample/project/releases?per_page=100&page=1"] = URLError("synthetic unavailable")
                with patch("subprocess.run") as command, self.assertRaises((ValueError, URLError)):
                    self.invoke(bundle, FakeAPI(responses), env)
                command.assert_not_called()

    def test_partial_create_failure_never_updates_clobbers_deletes_or_retries(self):
        with release_bundle() as bundle:
            api = FakeAPI(self.responses(bundle))
            before = {path.name: path.read_bytes() for path in bundle.dist.iterdir()}
            calls_at_failure = []
            def fail(argv, **kwargs):
                calls_at_failure.append(len(api.calls))
                raise subprocess.CalledProcessError(1, argv)
            with patch("subprocess.run", side_effect=fail) as command, self.assertRaisesRegex(RuntimeError, "partial draft"):
                self.invoke(bundle, api, publish_environment(bundle))
            command.assert_called_once()
            self.assertEqual(calls_at_failure, [len(api.calls)], "failure must not start cleanup API requests")
            self.assertEqual(command.call_args.args[0][:3], ["gh", "release", "create"])
            self.assertEqual(before, {path.name: path.read_bytes() for path in bundle.dist.iterdir()})

    def test_publish_entry_rechecks_every_dependency_and_artifact_provenance(self):
        for dependency in ("prepare", "quality", "build", "assemble", "gate"):
            for state in ("failure", "skipped", "cancelled", None):
                with self.subTest(dependency=dependency, state=state), release_bundle() as bundle:
                    env = publish_environment(bundle)
                    needs = json.loads(env["NEEDS_JSON"])
                    if state is None:
                        del needs[dependency]
                    else:
                        needs[dependency]["result"] = state
                    env["NEEDS_JSON"] = json.dumps(needs)
                    api = FakeAPI(self.responses(bundle))
                    with patch("subprocess.run") as command, self.assertRaises(ValueError):
                        self.invoke(bundle, api, env)
                    self.assertEqual(api.calls, [], "non-success dependencies must reject before any publication preflight")
                    command.assert_not_called()
        with release_bundle() as bundle:
            bundle.change_manifest(["release", "source_commit"], oid("caller-a"))
            with patch("subprocess.run") as command, self.assertRaises(ValueError):
                self.invoke(bundle, FakeAPI(self.responses(bundle)), publish_environment(bundle))
            command.assert_not_called()


class PullRequestIdentityTests(unittest.TestCase):
    def test_pr_api_head_h_and_checkout_merge_m_are_distinct_required_identities(self):
        head, merge = oid("pr-branch-head-h"), oid("pr-merge-m")
        event = {"pull_request": {"head": {"sha": head}}}
        for name, ident, control in gate_controls():
            with self.subTest(workflow=name, job=ident):
                self.assertEqual(control["expected_api_head"]("pull_request", event, merge), head)
                for non_pr in ("push", "workflow_dispatch", "schedule"):
                    self.assertEqual(control["expected_api_head"](non_pr, event, oid("caller-a")), oid("caller-a"))
        for name, ident in (("ci.yml", "test"), ("release-verify.yml", "build"), ("release-verify.yml", "assemble")):
            control, _ = load_step(name, ident, "assert_source")
            with self.subTest(workflow=name, job=ident), patch("subprocess.check_output", return_value=merge + "\n"):
                control["assert_source"](merge)
            with self.subTest(workflow=name, job=ident), patch("subprocess.check_output", return_value=head + "\n"), self.assertRaises(ValueError):
                control["assert_source"](merge)

    def test_missing_or_invalid_pr_head_never_falls_back_to_merge_sha(self):
        merge = oid("pr-merge-m")
        bad_events = [None, [], {}, {"pull_request": None}, {"pull_request": {}}, {"pull_request": {"head": None}}]
        for value in (None, "", "0" * 40, "A" * 40, "short", 123, oid("pr-branch-head-h") + "\n"):
            bad_events.append({"pull_request": {"head": {"sha": value}}})
        for name, ident, control in gate_controls():
            for event in bad_events:
                with self.subTest(workflow=name, job=ident, event=event), self.assertRaises(ValueError):
                    control["expected_api_head"]("pull_request", event, merge)
            for kind in ("", "workflow_call", "pull_request_target", "unknown"):
                with self.subTest(workflow=name, job=ident, kind=kind), self.assertRaises(ValueError):
                    control["expected_api_head"](kind, {}, merge)

    def test_actual_pr_gate_main_accepts_h_rejects_swapped_m_and_malformed_head(self):
        head, merge = oid("pr-branch-head-h"), oid("pr-merge-m")
        endpoint = "repos/sample/project/actions/runs/501/attempts/2/jobs?per_page=100&page=1"
        for name in ("ci.yml", "release-verify.yml"):
            control, source = load_step(name, "gate", "gate")
            records = [job_record(leaf, index) for index, leaf in enumerate(expected_gate_leaves(name), 1)]
            for record in records:
                record["head_sha"] = head
            env = gate_environment(name, merge)
            with gate_event("pull_request", {"pull_request": {"head": {"sha": head}}}) as event_env:
                env.update(event_env)
                api = FakeAPI({endpoint: {"total_count": len(records), "jobs": records}})
                with self.subTest(workflow=name, case="H with M checkout"), patch.dict(control, {"api_get": api}):
                    run_main(control, source, env)
                swapped = copy.deepcopy(records)
                for record in swapped:
                    record["head_sha"] = merge
                api = FakeAPI({endpoint: {"total_count": len(swapped), "jobs": swapped}})
                with self.subTest(workflow=name, case="M as API head"), patch.dict(control, {"api_get": api}), self.assertRaises(ValueError):
                    run_main(control, source, env)
            for malformed in ({}, {"pull_request": {"head": {"sha": ""}}}):
                with gate_event("pull_request", malformed) as event_env:
                    env.update(event_env)
                    api = FakeAPI({endpoint: {"total_count": len(records), "jobs": records}})
                    with self.subTest(workflow=name, malformed=malformed), patch.dict(control, {"api_get": api}), self.assertRaises(ValueError):
                        run_main(control, source, env)
                    self.assertEqual(api.calls, [], "invalid PR identity must stop before API inventory reads")


class PipelineSourceTests(unittest.TestCase):
    def test_dispatch_a_tag_b_outputs_b_for_quality_build_and_assembly(self):
        prepare, source = load_step("release.yml", "prepare", "release")
        with release_bundle() as bundle:
            output = bundle.base / "prepared-output"
            tag_object = oid("original-annotation")
            api = FakeAPI({
                f"repos/sample/project/git/ref/tags/{bundle.tag}": tag_response(bundle.tag, tag_object, "tag"),
                f"repos/sample/project/git/tags/{tag_object}": {
                    "sha": tag_object, "object": {"type": "commit", "sha": bundle.source_commit}},
            })
            env = {"EVENT_NAME": "workflow_dispatch", "EVENT_REF": "refs/heads/main",
                   "INPUTS_JSON": json.dumps({"tag": bundle.tag}), "GITHUB_REPOSITORY": "sample/project",
                   "CALLER_SHA": oid("caller-a"), "GITHUB_SHA": oid("caller-a"), "GITHUB_OUTPUT": str(output)}
            with patch.dict(prepare, {"api_get": api}):
                run_main(prepare, source, env)
            prepared = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
            self.assertEqual(prepared, {"tag": bundle.tag, "source_commit": bundle.source_commit, "tag_object": tag_object})
            ci, ci_source = load_step("ci.yml", "source", "source")
            run_main(ci, ci_source, {"SOURCE_COMMIT": prepared["source_commit"], "GITHUB_SHA": oid("caller-a")})
            for workflow, ident in (("ci.yml", "test"), ("ci.yml", "installer"),
                                    ("release.yml", "build"), ("release.yml", "assemble")):
                control, _ = load_step(workflow, ident, "assert_source")
                with self.subTest(workflow=workflow, job=ident), patch("subprocess.check_output", return_value=bundle.source_commit + "\n"):
                    control["assert_source"](prepared["source_commit"])
            validator, _ = load_step("release.yml", "assemble", "validate_artifacts")
            bundle.validate(validator, source_commit=prepared["source_commit"])

    def test_tag_push_uses_peeled_commit_not_annotated_object_as_caller_identity(self):
        control, source = load_step("release.yml", "prepare", "release")
        with tempfile.TemporaryDirectory(prefix="workflow-tag-") as directory:
            tag_object, commit = oid("original-annotation"), oid("tag-b")
            responses = {"repos/sample/project/git/ref/tags/v1.2.3": tag_response("v1.2.3", tag_object, "tag"),
                         f"repos/sample/project/git/tags/{tag_object}": {
                             "sha": tag_object, "object": {"type": "commit", "sha": commit}}}
            for caller in (commit, tag_object):
                output = Path(directory) / caller
                env = {"EVENT_NAME": "push", "EVENT_REF": "refs/tags/v1.2.3", "INPUTS_JSON": "{}",
                       "GITHUB_REPOSITORY": "sample/project", "CALLER_SHA": caller, "GITHUB_OUTPUT": str(output)}
                with patch.dict(control, {"api_get": FakeAPI(responses)}):
                    if caller == commit:
                        run_main(control, source, env)
                        self.assertIn("source_commit=" + commit, output.read_text(encoding="utf-8"))
                    else:
                        with self.assertRaises(ValueError):
                            run_main(control, source, env)
                        self.assertFalse(output.exists())

    def test_pr_prepare_keeps_merge_m_as_source_not_api_head_h(self):
        control, source = load_step("release-verify.yml", "prepare", "source")
        block = step("release-verify.yml", "prepare", "source")
        self.assertIn("SOURCE_COMMIT: ${{ github.sha }}", block)
        head, merge = oid("pr-branch-head-h"), oid("pr-merge-m")
        with tempfile.TemporaryDirectory(prefix="workflow-pr-") as directory:
            output = Path(directory) / "source-output"
            run_main(control, source, {"SOURCE_COMMIT": merge, "GITHUB_SHA": merge,
                                     "PR_HEAD": head, "GITHUB_OUTPUT": str(output)})
            self.assertEqual(output.read_text(encoding="utf-8"), "source_commit=" + merge + "\n")


class WorkflowBoundaryTests(unittest.TestCase):
    def test_all_checkouts_use_validated_source_and_do_not_persist_credentials(self):
        observed = 0
        for name in WORKFLOWS:
            for ident in jobs(name):
                for block in steps(name, ident):
                    if "uses: actions/checkout@" not in block:
                        continue
                    observed += 1
                    if name == "ci.yml":
                        source = "inputs.source_commit"
                    elif name == "security-audit.yml":
                        source = "needs.source.outputs.source_commit"
                    elif ident == "prepare":
                        source = "steps.release.outputs.source_commit" if name == "release.yml" else "steps.source.outputs.source_commit"
                    else:
                        source = "needs.prepare.outputs.source_commit"
                    with self.subTest(workflow=name, job=ident):
                        self.assertIn("ref: ${{ " + source + " }}", block)
                        self.assertIn("persist-credentials: false", block)
                        step(name, ident, "assert_source")
        self.assertGreaterEqual(observed, 9, "checkout coverage must not silently disappear")

    def test_aggregate_jobs_always_run_and_bind_complete_dependencies(self):
        for name in ("ci.yml", "release.yml", "release-verify.yml"):
            gate = job(name, "gate")
            expected = ["source", "test", "installer", "security"] if name == "ci.yml" else ["prepare", "quality", "build", "assemble"]
            with self.subTest(workflow=name):
                self.assertIn("    if: always()\n", gate)
                self.assertCountEqual(dependencies(gate), expected)
                self.assertIn("NEEDS_JSON: ${{ toJSON(needs) }}", step(name, "gate", "gate"))
                self.assertIn("EVENT_NAME: ${{ github.event_name }}", step(name, "gate", "gate"))
                self.assertIn("actions: read", top_block(read_workflow(name), "permissions"))
                self.assertNotIn("continue-on-error:", read_workflow(name))
        self.assertCountEqual(dependencies(job("release.yml", "publish")), ["prepare", "quality", "build", "assemble", "gate"])

    def test_required_named_commands_exist_with_only_intended_os_conditions(self):
        cases = [("ci.yml", "test", "test (ubuntu-latest)"),
                 ("ci.yml", "installer", "installer smoke (windows-latest)"),
                 ("ci.yml", "installer", "installer smoke (ubuntu-latest)"),
                 ("security-audit.yml", "dependency-audit", "Cargo dependency audit")]
        for name in ("release.yml", "release-verify.yml"):
            cases += [(name, "build", "build " + TARGETS[0]),
                      (name, "prepare", "resolve exact source and release inputs"),
                      (name, "assemble", "validate complete four-target unsigned bundle")]
        for name, ident, leaf in cases:
            for title in fixture_step_names(leaf):
                found = [block for block in steps(name, ident)
                         if re.search(r"(?m)^name: " + re.escape(title) + r"$", block)]
                with self.subTest(workflow=name, job=ident, step=title):
                    self.assertEqual(len(found), 1, "mandatory step missing or duplicated")
                    block = found[0]
                    platform = "windows" if title.endswith("(windows)") else "unix" if title.endswith("(unix)") else None
                    if platform:
                        condition = "runner.os == 'Windows'" if platform == "windows" else "runner.os != 'Windows'"
                        self.assertIn("if: " + condition, block)
                    else:
                        self.assertNotRegex(block, r"(?m)^        if:")
                    self.assertNotIn("continue-on-error:", block)

    def test_three_os_quality_and_all_existing_command_families_remain(self):
        for ident in ("test", "installer"):
            block = job("ci.yml", ident)
            match = re.search(r"(?m)^        os: \[([^\]]+)\]$", block)
            self.assertIsNotNone(match)
            runners = [item.strip() for item in match[1].split(",")]
            self.assertCountEqual(runners, ["ubuntu-latest", "windows-latest", "macos-latest"])
        quality = job("ci.yml", "test")
        for command in (
            "cargo fmt --all --check", "cargo clippy --workspace --all-targets -- -D warnings", "cargo test --workspace",
            "node --test crates/agent-session-grep-cli/tests/web_ui.test.cjs",
            "cargo test -p agent-session-grep-application --features semantic-candle",
            "cargo check -p agent-session-grep-cli --all-targets --features semantic-candle",
            "cargo test -p agent-session-grep-cli --test e2e robot_",
            'python -m unittest discover -s scripts -p "test_*.py"',
            'python -m unittest discover -s scripts/release -p "test_*.py"',
            'python -m unittest discover -s scripts/evidence -p "test_*.py"',
        ):
            self.assertIn(command, quality)
        installer = job("ci.yml", "installer")
        for command in ("cargo build --locked --release -p agent-session-grep-cli", "--skip-build", "-SkipBuild",
                        "scripts/install/smoke.sh", "scripts/install/smoke.ps1", "test_real_data_regression.py",
                        "./ci-prefix/agent-session-grep", "./ci-prefix/asg"):
            self.assertIn(command, installer)
        self.assertEqual(installer.count("./scripts/install/uninstall.sh --prefix"), 2)
        control, source = load_step("ci.yml", "installer", "uninstall_twice")
        with tempfile.TemporaryDirectory(prefix="workflow-commands-") as directory, \
                contextlib.chdir(directory), patch("subprocess.run") as command:
            run_main(control, source, {})
        self.assertEqual([call.args[0][4:6] for call in command.call_args_list],
                         [["./scripts/install/uninstall.ps1", "-Prefix"]] * 2)
        self.assertTrue(all(call.kwargs.get("check") is True for call in command.call_args_list))

    def test_write_job_executes_only_trusted_inline_control_and_verified_gh_create(self):
        block = job("release.yml", "publish")
        _, source = load_step("release.yml", "publish", "publish")
        tree = ast.parse(source)
        gh_calls = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [item.name for item in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                for module in modules:
                    root = module.split(".")[0]
                    self.assertIn(root, sys.stdlib_module_names)
                    self.assertNotIn(root, {"importlib", "runpy"})
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"eval", "exec", "compile", "__import__"})
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                self.assertNotIn((node.func.value.id, node.func.attr), {("os", "system"), ("os", "popen")})
                if node.func.value.id == "subprocess":
                    self.assertEqual(node.func.attr, "run")
                    self.assertTrue(node.args and isinstance(node.args[0], ast.List))
                    self.assertEqual([item.value for item in node.args[0].elts[:3]], ["gh", "release", "create"])
                    gh_calls.append(node)
        self.assertEqual(len(gh_calls), 1)
        references = re.findall(r"(?m)^        uses: ([^@\s]+)@", block)
        self.assertTrue(references)
        self.assertTrue(set(references).issubset({"actions/download-artifact", "actions/setup-python"}))
        for name in WORKFLOWS:
            text = read_workflow(name)
            self.assertNotIn("pull_request_target", text)
            self.assertNotIn("secrets:", text)
        verify = read_workflow("release-verify.yml")
        self.assertNotRegex(verify, r"\bgh\s+release\b|\bgit\s+(?:tag|push)\b")
        self.assertNotIn("merge-multiple: true", verify)
        self.assertNotIn("merge-multiple: true", read_workflow("release.yml"))


class ControlExtractionTests(unittest.TestCase):
    def test_python_gh_detection_stops_before_the_next_job_and_ignores_comments(self):
        header = "name: synthetic\n        shell: python {0}\n        run: |\n"
        tail = "\n  publish:\n    name: publish a new unsigned GitHub Release only\n"
        literal = header + '          import subprocess\n          subprocess.run(["gh", "release", "create", "v1.2.3"], check=True)\n' + tail
        self.assertTrue(has_python_gh_call(literal))
        comments = header + '          # gh release create is not executed\n          text = "gh release create"\n' + tail
        self.assertFalse(has_python_gh_call(comments))
        self.assertNotIn("publish a new", run_source(comments))

    def test_missing_duplicate_or_nonliteral_control_is_not_silently_accepted(self):
        missing = "name: synthetic\n        shell: python {0}\n        run: print('not literal')\n"
        with self.assertRaises(AssertionError):
            run_source(missing)
        workflow = "name: synthetic\non:\n  workflow_call:\njobs:\n  control:\n    runs-on: ubuntu-latest\n    steps:\n"
        control = "      - name: synthetic\n        id: inspect\n        shell: python {0}\n        run: |\n          value = 1\n"
        with patch(__name__ + ".read_workflow", return_value=workflow + control + control):
            with self.assertRaises(AssertionError):
                load_step("synthetic.yml", "control", "inspect")
        with patch(__name__ + ".read_workflow", return_value=workflow):
            with self.assertRaises(AssertionError):
                load_step("synthetic.yml", "control", "inspect")


class InputContextTests(unittest.TestCase):
    def test_release_push_ignores_inputs_but_manual_requires_an_object_and_tag(self):
        control, _ = load_step("release.yml", "prepare", "release")
        for inputs in (None, "", [], 0, "malformed unused scalar", {"tag": "v9.9.9"}):
            with self.subTest(inputs=inputs):
                self.assertEqual(control["select_tag"]("push", "refs/tags/v1.2.3", inputs), "v1.2.3")
                with self.assertRaises(ValueError):
                    control["select_tag"]("push", "refs/heads/main", inputs)
        for inputs in (None, "", [], 0, False, "v1.2.3", {}, {"tag": None}, {"tag": ""}, {"tag": 7}):
            with self.subTest(inputs=inputs), self.assertRaises(ValueError):
                control["select_tag"]("workflow_dispatch", "refs/tags/v1.2.3", inputs)

    def test_actual_release_entry_only_parses_inputs_for_manual_dispatch(self):
        control, source = load_step("release.yml", "prepare", "release")
        responses = {"repos/sample/project/git/ref/tags/v1.2.3": tag_response()}
        unavailable_or_bad = ("", "null", '""', "{", "[]", "0", "false", "{}", '{"tag":""}')
        with tempfile.TemporaryDirectory(prefix="workflow-input-") as directory:
            for index, raw in enumerate(unavailable_or_bad):
                for event in ("push", "workflow_dispatch"):
                    output = Path(directory) / f"{event}-{index}"
                    env = {"EVENT_NAME": event, "EVENT_REF": "refs/tags/v1.2.3", "INPUTS_JSON": raw,
                           "GITHUB_REPOSITORY": "sample/project", "CALLER_SHA": oid("tag-b"), "GITHUB_OUTPUT": str(output)}
                    api = FakeAPI(responses)
                    with self.subTest(event=event, raw=raw), patch.dict(control, {"api_get": api}), \
                            patch("subprocess.run") as command, patch("os.system") as shell:
                        if event == "push":
                            run_main(control, source, env)
                            self.assertIn("source_commit=" + oid("tag-b"), output.read_text(encoding="utf-8"))
                        else:
                            with self.assertRaises(ValueError):
                                run_main(control, source, env)
                            self.assertEqual(api.calls, [])
                            self.assertFalse(output.exists())
                        command.assert_not_called()
                        shell.assert_not_called()

    def test_actual_audit_entry_normalizes_only_unavailable_standalone_context(self):
        control, source = load_step("security-audit.yml", "source", "source")
        hostile = "$(echo injected)\nsource_commit=wrong"
        supplied = json.dumps({"source_commit": oid("tag-b"), "tag": hostile, "caller_metadata": {"unused": hostile}})
        with tempfile.TemporaryDirectory(prefix="workflow-input-") as directory:
            for event in ("schedule", "workflow_dispatch", "push", "pull_request"):
                for index, raw in enumerate(("", "null", '""', "{}", supplied)):
                    output = Path(directory) / f"{event}-{index}"
                    env = {"EVENT_NAME": event, "INPUTS_JSON": raw, "CALLER_SHA": oid("caller-a"), "GITHUB_OUTPUT": str(output)}
                    with self.subTest(event=event, raw=raw), patch("subprocess.run") as command, patch("os.system") as shell:
                        if raw == supplied or event in {"schedule", "workflow_dispatch"}:
                            run_main(control, source, env)
                            expected = oid("tag-b") if raw == supplied else oid("caller-a")
                            self.assertEqual(output.read_text(encoding="utf-8"), "source_commit=" + expected + "\n")
                            self.assertNotIn(hostile, output.read_text(encoding="utf-8"))
                        else:
                            with self.assertRaises(ValueError):
                                run_main(control, source, env)
                            self.assertFalse(output.exists())
                        command.assert_not_called()
                        shell.assert_not_called()

    def test_audit_present_empty_source_and_malformed_context_never_use_caller(self):
        control, source = load_step("security-audit.yml", "source", "source")
        bad_raw = (" ", "{", "[]", "0", "false", '"scalar"', '" "',
                   json.dumps({"source_commit": None, "tag": "v1.2.3"}),
                   json.dumps({"source_commit": "", "tag": "v1.2.3"}),
                   json.dumps({"source_commit": "0" * 40, "tag": "v1.2.3"}),
                   json.dumps({"tag": "v1.2.3"}))
        with tempfile.TemporaryDirectory(prefix="workflow-input-") as directory:
            for event in ("schedule", "workflow_dispatch", "push", "pull_request"):
                for index, raw in enumerate(bad_raw):
                    output = Path(directory) / f"{event}-{index}"
                    env = {"EVENT_NAME": event, "INPUTS_JSON": raw, "CALLER_SHA": oid("caller-a"), "GITHUB_OUTPUT": str(output)}
                    with self.subTest(event=event, raw=raw), self.assertRaises(ValueError):
                        run_main(control, source, env)
                    self.assertFalse(output.exists())

    def test_both_reusable_quality_interfaces_require_source_commit(self):
        for name in ("ci.yml", "security-audit.yml"):
            trigger = top_block(read_workflow(name), "on")
            found = re.findall(r"(?m)^      source_commit:\n((?:        [^\n]*\n|\n)*)", trigger)
            with self.subTest(workflow=name):
                self.assertEqual(len(found), 1)
                self.assertRegex(found[0], r"(?m)^        required: true$")
                self.assertRegex(found[0], r"(?m)^        type: string$")
                self.assertNotIn("default:", found[0])


if __name__ == "__main__":
    unittest.main()
