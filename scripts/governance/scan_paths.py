"""Offline path privacy over exact tree, introduced history and metadata."""
import importlib.util
from pathlib import Path
import sys

from common import Parser, GitRepo, digest, fail, main_guard, sha
from check_pr import scan_metadata
from credential_scan import (Surface, collect_surfaces, content_surfaces,
                             validate_text_surface)

ROOT = Path(__file__).resolve().parent


def path_content_surfaces(kind, path, data):
    # Same strict text/binary/SQLite coverage as the credential gate, with the
    # ORIGINAL relative path retained for the unchanged trusted exact allowlist.
    decoded = content_surfaces(kind, path, data)[-1].data
    return [Surface(kind, path, decoded)]


def scan_paths(surfaces, coverage):
    # Load only alongside this reviewed checker, never from candidate --repo.
    spec = importlib.util.spec_from_file_location(
        "governance_path_privacy", ROOT.parent / "evidence" / "privacy_scan.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    for surface in surfaces:
        validate_text_surface(surface.data)
        if module.scan_content(surface.path or "metadata", surface.data, "public"):
            fail("path-privacy-findings")
    return {"findings": 0, "coverage": coverage, "profile": "public"}


def main():
    parser = Parser(description=__doc__, epilog=(
        "Reuses trusted existing path rules unchanged; credential scanning is a "
        "separate required gate. No candidate config/allowlist is imported. "
        "Range is reachable(head) minus reachable(base), including merges. "
        "Whole history covers ONLY selected head ancestry, not all refs/tags, "
        "release assets or other publication surfaces. Unknown coverage rejects."))
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", help="Exact current target tip")
    parser.add_argument("--head", required=True, help="Exact candidate commit")
    parser.add_argument("--whole-history", action="store_true")
    parser.add_argument("--event-file")
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--merge-message-file")
    parser.add_argument("--merge-metadata-file")
    args = parser.parse_args()
    if args.whole_history == bool(args.base):
        fail("choose-range-or-whole-history")
    sha(args.head)
    if args.base:
        sha(args.base)
    surfaces, coverage = collect_surfaces(GitRepo(args.repo), args.base, args.head,
                                          content_factory=path_content_surfaces)
    metadata, payloads = scan_metadata(args)
    surfaces.extend(Surface("metadata", "", data) for data in payloads)
    result = scan_paths(surfaces, coverage)
    result.update({"status": "passed", "base": args.base, "head": args.head,
                   "scope": "whole-history" if args.whole_history else "introduced-history-and-head",
                   "history_selection": "selected-head-ancestry" if args.whole_history else "head-minus-base",
                   "all_refs_scanned": False, "published_assets_scanned": False,
                   "metadata_sha256": digest(metadata), "event_scanned": bool(args.event_file),
                   "merge_message_scanned": bool(args.merge_message_file),
                   "merge_identities_scanned": bool(args.merge_metadata_file),
                   "credential_check": "separate-required-check"})
    return result


if __name__ == "__main__":
    raise SystemExit(main_guard(main))
