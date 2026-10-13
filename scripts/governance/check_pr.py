"""Check PR event metadata; optionally bind it to the complete local graph."""
from common import Parser, GitRepo, decode, digest, fail, main_guard, parse_json, read_bytes, sha
from policy import (POLICY, validate_body, validate_commit, validate_header,
                    validate_merge_metadata, validate_message)


def event_fields(event):
    if not isinstance(event, dict) or event.get("action") not in (
            "opened", "synchronize", "reopened", "edited", "ready_for_review"):
        fail("unsupported-pr-event")
    try:
        pr = event["pull_request"]
        repo_id = event["repository"]["id"]
        number = event["number"]
        if (type(repo_id) is not int or repo_id <= 0 or type(number) is not int or number <= 0
                or type(pr["number"]) is not int or pr["number"] != number
                or type(pr["base"]["repo"]["id"]) is not int or pr["base"]["repo"]["id"] != repo_id):
            fail("invalid-event-identity")
        fields = {"repository_id": repo_id, "number": number,
                  "base": sha(pr["base"]["sha"]), "head": sha(pr["head"]["sha"]),
                  "title": pr["title"], "body": pr["body"], "action": event["action"]}
        if not isinstance(fields["title"], str) or not isinstance(fields["body"], str):
            fail("pr-text-required")
        return fields
    except (KeyError, TypeError):
        fail("incomplete-pr-event")



def decoded_json_strings(value):
    """All JSON keys and string values, without escape sequences hiding data."""
    if isinstance(value, str):
        yield value.encode("utf-8")
    elif isinstance(value, dict):
        for key, child in value.items():
            yield key.encode("utf-8")
            yield from decoded_json_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from decoded_json_strings(child)


def scan_metadata(args):
    """One explicit event/merge-data boundary shared by both privacy gates."""
    metadata, payloads = {}, []
    if args.event_file:
        raw = read_bytes(args.event_file)
        event = parse_json(raw)
        fields = event_fields(event)
        if (fields["head"] != args.head or (args.base and fields["base"] != args.base)
                or (args.repository_id is not None and fields["repository_id"] != args.repository_id)):
            fail("stale-or-wrong-event")
        metadata["event"] = event
        payloads.extend([raw, *decoded_json_strings(event)])
    elif args.repository_id is not None:
        fail("event-required")
    if args.merge_message_file:
        raw = read_bytes(args.merge_message_file)
        metadata["merge_message"] = decode(raw)
        payloads.append(raw)
    if args.merge_metadata_file:
        if not args.merge_message_file:
            fail("merge-message-required")
        raw = read_bytes(args.merge_metadata_file)
        value = parse_json(raw)
        validate_merge_metadata(value)
        metadata["merge_identities"] = value
        payloads.extend([raw, *decoded_json_strings(value)])
    return metadata, payloads


def validate_event(event, *, repo=None, expected_base=None, expected_head=None,
                   repository_id=None, merge_message=None, merge_metadata=None):
    fields = event_fields(event)
    fields["event_sha256"] = digest(event)
    for key, expected in [("base", expected_base), ("head", expected_head),
                          ("repository_id", repository_id)]:
        if expected is not None and fields[key] != expected:
            fail("stale-or-wrong-event")
    validate_header(fields["title"])
    validate_body(fields["body"])
    count = None
    if repo is not None:
        commits = repo.range(fields["base"], fields["head"])
        for commit in commits:
            validate_commit(commit)
        count = len(commits)
    if merge_message is not None:
        validate_message(merge_message)
        fields["merge_message"] = merge_message
    if merge_metadata is not None:
        if merge_message is None:
            fail("merge-message-required")
        validate_merge_metadata(merge_metadata)
        fields["merge_metadata"] = merge_metadata
    return {"status": "passed", "scope": "pr-and-range" if repo else "pr-metadata-only",
            "policy": POLICY["version"], "base": fields["base"], "head": fields["head"],
            "commits": count, "metadata_sha256": digest(fields), "human_review_required": True}


def main():
    parser = Parser(description=__doc__, epilog=(
        "Event-file mode alone never certifies commit history. Supply --repo for all "
        "newly reachable commits. Re-run on every edit and bind approval to the "
        "output metadata_sha256 as well as base/head. No GitHub API pagination is used. "
        "Trusted workflow must independently fetch fresh base/head/event evidence."))
    parser.add_argument("--event-file", required=True, help="Complete GitHub pull_request event JSON")
    parser.add_argument("--repo", help="Full local repository for introduced-commit validation")
    parser.add_argument("--expected-base", help="Independently observed current base SHA")
    parser.add_argument("--expected-head", help="Independently observed candidate head SHA")
    parser.add_argument("--repository-id", type=int, help="Independently trusted numeric repository ID")
    parser.add_argument("--merge-message-file", help="UTF-8 exact proposed merge message")
    parser.add_argument("--merge-metadata-file", help='JSON {author:{name,email},committer:{name,email}}')
    args = parser.parse_args()
    return validate_event(parse_json(read_bytes(args.event_file)),
                          repo=GitRepo(args.repo) if args.repo else None,
                          expected_base=sha(args.expected_base) if args.expected_base else None,
                          expected_head=sha(args.expected_head) if args.expected_head else None,
                          repository_id=args.repository_id,
                          merge_message=decode(read_bytes(args.merge_message_file)) if args.merge_message_file else None,
                          merge_metadata=parse_json(read_bytes(args.merge_metadata_file)) if args.merge_metadata_file else None)


if __name__ == "__main__":
    raise SystemExit(main_guard(main))
