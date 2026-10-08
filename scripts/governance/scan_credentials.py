"""Fail-closed offline credential gate, separate from the existing path scanner."""
from common import Parser, GitRepo, digest, fail, main_guard, sha
from check_pr import scan_metadata
from credential_scan import Scanner, Surface, collect_surfaces
from provision_gitleaks import ASSETS


def main():
    parser = Parser(description=__doc__, epilog=(
        "Scans exact HEAD plus introduced postimages (including added-then-deleted "
        "content and new path contexts), raw new commit messages/identities. "
        "Range: reachable(head) minus reachable(base), NOT base-as-ancestor. "
        "--whole-history is a distinct existing-formal-history audit, never an "
        "implicit baseline exemption. It covers only selected head ancestry, NOT all "
        "refs/tags, release assets or other published surfaces. Unsupported binary/archive/encoding/size "
        "is rejection. No candidate config/baseline/inline allow is accepted. "
        "Run from a separately owner-reviewed trusted tool checkout."))
    parser.add_argument("--repo", required=True, help="Complete local Git repository; no checkout executed")
    parser.add_argument("--base", help="Exact lowercase 40-hex current target tip")
    parser.add_argument("--head", required=True, help="Exact lowercase 40-hex candidate commit")
    parser.add_argument("--whole-history", action="store_true", help="Scan all head ancestry; forbids --base")
    parser.add_argument("--gitleaks-archive", required=True, help="Offline pinned release archive; verified before execution")
    parser.add_argument("--platform", choices=tuple(ASSETS), help="Defaults to supported native platform")
    parser.add_argument("--event-file", help="Complete GitHub PR event; base/head must match range")
    parser.add_argument("--repository-id", type=int, help="Independently trusted event repository ID")
    parser.add_argument("--merge-message-file", help="Exact UTF-8 proposed merge message, separate surface")
    parser.add_argument("--merge-metadata-file", help='JSON {author:{name,email},committer:{name,email}}')
    args = parser.parse_args()
    if args.whole_history == bool(args.base):
        fail("choose-range-or-whole-history")
    sha(args.head)
    if args.base:
        sha(args.base)
    scanner = Scanner(args.gitleaks_archive, args.platform)
    surfaces, coverage = collect_surfaces(GitRepo(args.repo), args.base, args.head)
    metadata, payloads = scan_metadata(args)
    surfaces.extend(Surface("metadata", "", data) for data in payloads)
    result = scanner.scan(surfaces)
    result.update({"status": "passed", "scope": "whole-history" if args.whole_history else "introduced-history-and-head",
                   "base": args.base, "head": args.head, "coverage": coverage,
                   "history_selection": "selected-head-ancestry" if args.whole_history else "head-minus-base",
                   "all_refs_scanned": False, "published_assets_scanned": False,
                   "metadata_sha256": digest(metadata), "event_scanned": bool(args.event_file),
                   "merge_message_scanned": bool(args.merge_message_file),
                   "merge_identities_scanned": bool(args.merge_metadata_file),
                   "path_privacy_check": "separate-required-check"})
    return result


if __name__ == "__main__":
    raise SystemExit(main_guard(main))
