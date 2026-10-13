"""Shared bounded, non-shell Git/data boundary. Errors never include input data."""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

MAX_INPUT = 2 * 1024 * 1024
MAX_BLOB = 16 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


class GateError(Exception):
    """A fixed, reviewed diagnostic code, never an underlying exception."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise GateError("invalid-arguments")


def fail(code):
    raise GateError(code)


def read_bytes(path, limit=MAX_INPUT):
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        fail("input-size-limit")
    return data


def decode(data):
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeError:
        fail("unsupported-encoding")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate-json-key")
        result[key] = value
    return result


def parse_json(data):
    try:
        return json.loads(decode(data), object_pairs_hook=_object,
                          parse_constant=lambda value: fail("invalid-json-number"))
    except (ValueError, RecursionError):
        fail("invalid-json")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(",", ":")).encode()).hexdigest()


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        fail("full-sha1-required")
    return value


def clean_env():
    # Do not inherit GIT_*, GITLEAKS_*, proxy, loader or credential variables.
    keys = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"}
    env = {k: v for k, v in os.environ.items() if k.upper() in keys}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "", "LC_ALL": "C", "NO_COLOR": "1"})
    return env


def run(argv, *, cwd=None, data=None, timeout=120, limit=MAX_BLOB):
    # Temporary outputs stay private, bounded on read, and never reach the log.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.run(argv, input=data, stdout=out, stderr=err,
                                  cwd=cwd, env=clean_env(), timeout=timeout,
                                  shell=False, check=False)
        except subprocess.TimeoutExpired:
            fail("tool-timeout")
        except OSError:
            fail("tool-unavailable")
        out.seek(0)
        result = out.read(limit + 1)
        if len(result) > limit:
            fail("tool-output-limit")
        return proc.returncode, result


@dataclass(frozen=True)
class Commit:
    oid: str
    parents: tuple
    message: str
    author: dict
    committer: dict
    raw: bytes


def identity_header(value):
    match = re.fullmatch(r"(.+) <([^<>\s]+)> (-?[0-9]+) ([+-][0-9]{4})", value)
    if not match:
        fail("invalid-git-identity")
    return {"name": match[1], "email": match[2]}


class GitRepo:
    def __init__(self, path):
        self.path = Path(path).resolve(strict=True)
        self.executable = shutil.which("git")
        if not self.executable:
            fail("git-unavailable")
        # Even currently available promisor objects do not certify an offline
        # complete graph. Reject partial-clone configuration before traversal.
        config = self.git("config", "--null", "--list")
        if re.search(rb"(?:^|\x00)(?:extensions\.partialclone|remote\.[^\x00\n]+\.promisor)\n", config, re.I):
            fail("partial-clone-graph")
        if self.git("rev-parse", "--is-shallow-repository").strip() != b"false":
            fail("shallow-graph")
        if self.git("for-each-ref", "--format=%(refname)", "refs/replace").strip():
            fail("replacement-graph")
        graft = Path(decode(self.git("rev-parse", "--git-path", "info/grafts")).strip())
        if not graft.is_absolute():
            graft = self.path / graft
        if graft.exists() and graft.stat().st_size:
            fail("grafted-graph")

    def git(self, *args, data=None, limit=MAX_BLOB):
        code, out = run([self.executable, "--no-replace-objects", "-c",
                         "core.fsmonitor=false", "-c", "core.hooksPath=",
                         "-c", "protocol.allow=never", "-C", str(self.path), *args],
                        data=data, limit=limit)
        if code:
            fail("git-evidence-incomplete")
        return out

    def require_commit(self, oid):
        sha(oid)
        if self.git("cat-file", "-t", oid).strip() != b"commit":
            fail("commit-object-required")

    def verify_graph(self, base, head):
        self.require_commit(head)
        if base is not None:
            self.require_commit(base)
            if not self.git("merge-base", base, head).strip():
                fail("unrelated-history")
        tips = [head] if base is None else [base, head]
        # Traverses both complete reachable graphs, not paginated API results.
        objects = self.git("rev-list", "--objects", "--no-object-names", *tips)
        checked = self.git("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                           data=objects)
        names = objects.splitlines()
        rows = checked.splitlines()
        if not names or len(names) != len(rows):
            fail("incomplete-object-inventory")
        for expected, row in zip(names, rows):
            fields = row.split()
            if (len(fields) != 3 or fields[0] != expected or
                    fields[1] not in (b"commit", b"tree", b"blob", b"tag") or
                    not fields[2].isdigit()):
                fail("missing-git-object")

    def range(self, base, head):
        self.verify_graph(base, head)
        args = ["rev-list", "--reverse", "--topo-order", head]
        if base is not None:
            args.extend(["--not", base])
        return [self.commit(sha(line)) for line in decode(self.git(*args)).splitlines()]

    def commit(self, oid):
        raw = self.git("cat-file", "commit", sha(oid), limit=MAX_INPUT)
        text = decode(raw)
        header, separator, message = text.partition("\n\n")
        if not separator:
            fail("invalid-commit-object")
        values = {}
        for line in header.split("\n"):
            if line.startswith(" "):
                continue  # Signatures are still included in raw credential scanning.
            key, sep, value = line.partition(" ")
            if not sep:
                fail("invalid-commit-header")
            values.setdefault(key, []).append(value)
        if any(len(values.get(k, [])) != 1 for k in ("tree", "author", "committer")):
            fail("invalid-commit-header")
        if values.get("encoding", ["UTF-8"]) not in (["UTF-8"], ["utf-8"]):
            fail("unsupported-commit-encoding")
        return Commit(oid, tuple(sha(p) for p in values.get("parent", [])), message,
                      identity_header(values["author"][0]),
                      identity_header(values["committer"][0]), raw)

    def tree(self, oid):
        records = self.git("ls-tree", "-rz", "--full-tree", sha(oid))
        result = {}
        for record in records.split(b"\0"):
            if not record:
                continue
            header, separator, path = record.partition(b"\t")
            parts = header.split()
            if not separator or len(parts) != 3 or path in result:
                fail("invalid-tree-record")
            mode, kind, blob = parts
            # No checkout/path interpolation, symlink following or gitlinks.
            if mode not in (b"100644", b"100755") or kind != b"blob":
                fail("unsupported-tree-object")
            decode(path)
            result[path] = (mode, sha(decode(blob)))
        return result

    def blob(self, oid):
        size = self.git("cat-file", "-s", sha(oid)).strip()
        if not size.isdigit() or int(size) > MAX_BLOB:
            fail("blob-size-limit")
        return self.git("cat-file", "blob", oid)


def main_guard(main):
    try:
        result = main()
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
        return 0
    except GateError as exc:
        print(json.dumps({"status": "rejected", "code": str(exc)}), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        print('{"status":"rejected","code":"invalid-or-unavailable-input"}', file=sys.stderr)
        return 1
