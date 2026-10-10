"""Offline, explicit-coverage scanning. No path privacy exemptions live here."""
from dataclasses import dataclass
import base64
import binascii
import hashlib
import importlib.util
from pathlib import Path
import re
import sqlite3
import tempfile
from urllib.parse import unquote_to_bytes

from common import (MAX_BLOB, MAX_TOTAL, GateError, decode, fail, parse_json,
                    read_bytes, run)
from provision_gitleaks import (ASSETS, SOURCE, VERSION, extract_verified,
                               install_members, native_platform)

ROOT = Path(__file__).resolve().parent
try:
    REVIEWED = parse_json(read_bytes(ROOT / "reviewed_sqlite.json"))["fixtures"]
except (OSError, GateError, KeyError, TypeError):
    REVIEWED = None  # Missing trusted coverage evidence is never permission to skip.
ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00",
                 b"7z\xbc\xaf\x27\x1c", b"Rar!", b"\x28\xb5\x2f\xfd")


@dataclass(frozen=True)
class Surface:
    kind: str
    path: str
    data: bytes


def portable_paths(paths):
    # Reuse the trusted exporter path contract; do not load code from --repo.
    spec = importlib.util.spec_from_file_location(
        "governance_export_paths", ROOT.parent / "release" / "export_public_tree.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.validate_paths(paths)
    except ValueError:
        fail("unsafe-or-colliding-tree-path")


def sqlite_text(path, data):
    if REVIEWED is None:
        fail("trusted-binary-evidence-unavailable")
    entry = REVIEWED.get(path)
    if entry is None or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        fail("unreviewed-binary-content")
    # Pins authorize this decoding method, NOT bypassing credential scans.
    text, rows, cells, ff = [], 0, 0, 0
    with tempfile.TemporaryDirectory(prefix="governance-sqlite-") as directory:
        file = Path(directory) / "fixture.db"
        file.write_bytes(data)
        try:
            connection = sqlite3.connect(file.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                connection.execute("PRAGMA trusted_schema=OFF")
                if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    fail("sqlite-integrity-failure")
                if connection.execute("PRAGMA freelist_count").fetchone()[0] != 0:
                    fail("unreviewed-sqlite-free-pages")
                connection.text_factory = bytes
                schema = connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
                for name, sql in schema:
                    text.extend([name, sql or b""])
                    quoted = '"' + decode(name).replace('"', '""') + '"'
                    for row in connection.execute("SELECT * FROM " + quoted):
                        rows += 1
                        for cell in row:
                            if isinstance(cell, bytes):
                                try:
                                    cell.decode("utf-8")
                                except UnicodeError:
                                    if cell != bytes([255]):
                                        fail("unreviewed-sqlite-cell")
                                    ff += 1
                                else:
                                    cells += 1
                                    text.append(cell)
                            elif cell is not None:
                                text.append(str(cell).encode())
            finally:
                connection.close()
        except sqlite3.Error:
            fail("sqlite-decoding-failure")
    if (rows, cells, ff) != (entry["rows"], entry["text_cells"], entry["ff_cells"]):
        fail("sqlite-evidence-mismatch")
    # Printable raw regions also pass the scanner, not only live SQL cells.
    text.extend(re.findall(rb"[\x20-\x7e]{4,}", data))
    return b"\n".join(text)


def check_decode_depth(data, depth=0, budget=None):
    # Match the documented printable-text encoding families of the pinned CLI.
    # Detecting arbitrary encryption/obfuscation is explicitly not a claim.
    if budget is None:
        budget = [0]
    budget[0] += len(data)
    if budget[0] > MAX_TOTAL:
        fail("decoding-work-limit")
    candidates = []
    if re.search(rb"%[0-9A-Fa-f]{2}", data):
        candidates.append(unquote_to_bytes(data))
    for match in re.finditer(rb"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,}(?![A-Fa-f0-9])", data):
        if len(match[0]) % 2 == 0:
            candidates.append(bytes.fromhex(match[0].decode("ascii")))
    for match in re.finditer(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])", data):
        try:
            candidates.append(base64.b64decode(match[0] + b"=" * (-len(match[0]) % 4), validate=True))
        except (ValueError, binascii.Error):
            continue
    for decoded in candidates:
        if decoded == data:
            continue
        if decoded.startswith(ARCHIVE_MAGIC) or decoded.startswith(b"SQLite format 3\0"):
            fail("encoded-binary-coverage-required")
        try:
            text = decoded.decode("utf-8")
        except UnicodeError:
            continue
        if text and all(c.isprintable() or c in "\r\n\t" for c in text):
            if depth >= 5:
                fail("decode-depth-limit")
            check_decode_depth(decoded, depth + 1, budget)



def validate_text_surface(data):
    """Reject unsupported text before any scanner can silently skip it."""
    text = decode(data)
    if "\x00" in text:
        fail("binary-coverage-required")
    check_decode_depth(data)


def content_surfaces(kind, path, data):
    if REVIEWED is None:
        fail("trusted-binary-evidence-unavailable")
    if len(data) > MAX_BLOB:
        fail("blob-size-limit")
    if path in REVIEWED or data.startswith(b"SQLite format 3\0"):
        decoded = sqlite_text(path, data)
        check_decode_depth(decoded)
        return [Surface(kind, path, data), Surface("metadata", "", decoded)]
    if data.startswith(ARCHIVE_MAGIC) or data[257:262] == b"ustar":
        fail("archive-coverage-required")
    validate_text_surface(data)
    # Scan text via stdin too, so a built-in filename exclusion cannot hide
    # newly introduced credentials. Directory scan still retains path context.
    return [Surface(kind, path, data), Surface("metadata", "", data)]


def collect_surfaces(repo, base, head, *, content_factory=content_surfaces):
    commits = repo.range(base, head)
    trees = {}
    blobs = {}
    surfaces = []
    coverage = {"commits": len(commits), "tree_files": 0, "introduced_files": 0,
                "reviewed_sqlite": 0, "bytes": 0, "unsupported": 0}

    def tree(oid):
        if oid not in trees:
            trees[oid] = repo.tree(oid)
        return trees[oid]

    def add(kind, path, oid):
        if oid not in blobs:
            blobs[oid] = repo.blob(oid)
        payload = blobs[oid]
        coverage["bytes"] += len(payload)
        if coverage["bytes"] > MAX_TOTAL:
            fail("scan-total-size-limit")
        name = decode(path)
        surfaces.extend(content_factory(kind, name, payload))
        # Filenames are also data; never rely on scanner path filtering alone.
        surfaces.append(Surface("metadata", "", path))
        if name in REVIEWED:
            coverage["reviewed_sqlite"] += 1

    head_tree = tree(head)
    portable_paths([decode(p) for p in head_tree])
    for path, (_, oid) in head_tree.items():
        add("tree", path, oid)
        coverage["tree_files"] += 1
    seen = set()
    for index, commit in enumerate(commits):
        validate_text_surface(commit.raw)
        surfaces.append(Surface("metadata", "", commit.raw))
        current = tree(commit.oid)
        portable_paths([decode(p) for p in current])
        parents = [tree(p) for p in commit.parents]
        for path, entry in current.items():
            # Only postimages not inherited at this path from ANY direct parent.
            # Branch postimages are scanned when their own commits are visited.
            if any(parent.get(path) == entry for parent in parents):
                continue
            key = (path, entry)
            if key not in seen:
                seen.add(key)
                add(f"history/{index}", path, entry[1])
                coverage["introduced_files"] += 1
    return surfaces, coverage


def read_report(path, exit_code):
    if exit_code not in (0, 1):
        fail("scanner-error")
    try:
        report = parse_json(read_bytes(path, MAX_BLOB))
    except (OSError, GateError):
        fail("scanner-report-missing-or-invalid")
    if not isinstance(report, list):
        fail("scanner-report-missing-or-invalid")
    if exit_code == 0 and report:
        fail("scanner-inconsistent-result")
    if exit_code == 1:
        # Even malformed finding data must never be printed.
        if not report:
            fail("scanner-inconsistent-result")
        fail("credential-findings")
    return 0


class Scanner:
    def __init__(self, archive, platform=None):
        self.platform = platform or native_platform()
        if self.platform != native_platform():
            fail("scanner-platform-mismatch")
        self.members = extract_verified(archive, self.platform)
        self.binary_name = "gitleaks.exe" if self.platform == "windows_x64" else "gitleaks"
        self.binary_sha256 = hashlib.sha256(self.members[self.binary_name]).hexdigest()

    def scan(self, surfaces):
        with tempfile.TemporaryDirectory(prefix="governance-offline-") as directory:
            root = Path(directory)
            install_members(self.members, root / "tool")
            binary = root / "tool" / self.binary_name
            config = root / "trusted.toml"
            config.write_bytes(read_bytes(ROOT / "gitleaks.toml"))
            ignore = root / "empty.ignore"
            ignore.write_bytes(b"")
            code, version = run([str(binary), "version"], cwd=root)
            if code or version.strip() != VERSION.encode():
                fail("scanner-version-mismatch")
            target = root / "payload"
            target.mkdir()
            metadata = []
            by_kind = {}
            for surface in surfaces:
                if surface.kind == "metadata":
                    validate_text_surface(surface.data)
                    metadata.append(surface.data)
                    continue
                by_kind.setdefault(surface.kind, []).append(surface)
            for kind, group in by_kind.items():
                portable_paths([surface.path for surface in group])
                for surface in group:
                    file = target / kind / surface.path
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_bytes(surface.data)
            # Identifiers in kind are tool-generated, not candidate strings.
            report = root / "report.json"
            flags = ["--config", str(config), "--gitleaks-ignore-path", str(ignore),
                     "--ignore-gitleaks-allow", "--redact=100", "--no-banner", "--no-color",
                     "--log-level=error", "--exit-code=1", "--report-format=json",
                     "--report-path", str(report), "--max-target-megabytes=0",
                     "--max-decode-depth=5", "--max-archive-depth=0", "--timeout=120"]

            def invoke(command, data=None):
                if report.exists():
                    report.unlink()
                code, _ = run([str(binary), *command, *flags], cwd=root,
                              data=data, timeout=150)
                read_report(report, code)

            if by_kind:
                invoke(["dir", str(target)])
            # Metadata is independent of file rules/config/comments and is never
            # interpolated into argv. Delimiters prevent cross-record tokens.
            payload = b"\n\n".join(metadata)
            if len(payload) > MAX_TOTAL:
                fail("metadata-total-size-limit")
            invoke(["stdin"], payload)
            return {"scanner": VERSION, "scanner_source": SOURCE,
                    "archive_sha256": ASSETS[self.platform][1],
                    "binary_sha256": self.binary_sha256, "findings": 0,
                    "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                    "coverage_policy": {"text": "strict-utf8", "decode_depth": 5,
                                        "encodings": ["percent", "hex", "base64"],
                                        "archives": "rejected", "other_binary": "rejected",
                                        "sqlite": "exact-reviewed-hash-and-decoded-text",
                                        "max_blob_bytes": MAX_BLOB, "max_total_bytes": MAX_TOTAL}}
