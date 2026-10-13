"""Validate message files or every commit reachable from head but not base."""
from common import Parser, GitRepo, decode, fail, main_guard, read_bytes
from policy import POLICY, validate_commit, validate_message


def main():
    parser = Parser(description=__doc__, epilog=(
        "Range means reachable(head) minus reachable(base), including merges. "
        "Base is the exact current target tip, not necessarily an ancestor of head. "
        "Both graphs must be complete and have a common ancestor. "
        "Current-base freshness and genuine English/why/identity require human/server review."))
    parser.add_argument("--message-file", help="UTF-8 commit or proposed merge message; never rewritten")
    parser.add_argument("--repo", help="Local full Git graph (no shallow/replacement history)")
    parser.add_argument("--base", help="Exact lowercase 40-hex current target tip")
    parser.add_argument("--head", help="Exact lowercase 40-hex candidate commit")
    args = parser.parse_args()
    if args.message_file:
        if any((args.repo, args.base, args.head)):
            fail("choose-message-or-range")
        validate_message(decode(read_bytes(args.message_file)))
        return {"status": "passed", "scope": "message-syntax", "policy": POLICY["version"]}
    if not all((args.repo, args.base, args.head)):
        fail("complete-range-required")
    commits = GitRepo(args.repo).range(args.base, args.head)
    for commit in commits:
        validate_commit(commit)
    return {"status": "passed", "scope": "introduced-commit-syntax-and-identities",
            "base": args.base, "head": args.head, "commits": len(commits),
            "policy": POLICY["version"], "human_review_required": True}


if __name__ == "__main__":
    raise SystemExit(main_guard(main))
