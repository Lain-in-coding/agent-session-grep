"""One syntactic policy; language, truth, atomicity and approval remain human."""
from pathlib import Path
import re
import unicodedata
from common import GateError, fail, parse_json, read_bytes

try:
    POLICY = parse_json(read_bytes(Path(__file__).with_name("policy.json")))
except (OSError, GateError):
    POLICY = None  # Explicit non-success at the guarded CLI boundary, no fallback.
ADVERTISING = re.compile(
    r"(?:generated|authored|co-authored|written)\s+(?:by|with|using)\s+"
    r"(?:(?:the|an?)\s+)?[\[*_`~]*"
    r"(?:claude|chatgpt|copilot|codex|anthropic|openai|gemini|cursor)\b", re.I)
SKIP = re.compile(r"\[\s*(?:(?:skip[\s_-]+(?:ci|actions|checks?))|"
                  r"(?:(?:ci|actions|checks?)[\s_-]+skip)|no[\s_-]+ci)\s*\]|"
                  r"skip[\s_-]*checks\s*:\s*true", re.I)
TRAILER = re.compile(r"^(?:[A-Za-z][A-Za-z0-9-]*|BREAKING CHANGE)(?::(?: |$)| #)")
# Match complete placeholder fields, not engineering words inside prose.
PLACEHOLDER = re.compile(
    r"(?:TODO|TBD|TBA|FIXME|YOUR[_ ](?:SUMMARY|RATIONALE|REASON))[.!]?|"
    r"<[^>]*(?:why|summary|reason|rationale|describe)[^>]*>|"
    r"(?:fill in|fill out|replace this|replace me|describe why|describe the change)[.!]?",
    re.I)


def safe_text(text):
    if not isinstance(text, str):
        fail("text-required")
    text = text.replace("\r\n", "\n")
    if any(unicodedata.category(c).startswith("C") and c != "\n" for c in text):
        fail("hidden-or-control-character")
    if SKIP.search(text):
        fail("hidden-skip-directive")
    if ADVERTISING.search(text):
        fail("generated-attribution-advertising")
    return text


def validate_identity(identity):
    if not isinstance(identity, dict) or set(identity) != {"name", "email"}:
        fail("identity-fields-required")
    name, email = identity["name"], identity["email"]
    safe_text(name)
    safe_text(email)
    if (not name.strip() or name != name.strip() or "\n" in name or
            not re.fullmatch(r"[^<>\s@]+@[^<>\s@]+", email)):
        fail("invalid-identity")


def validate_coauthor(identity):
    validate_identity(identity)
    # A generic Git name cannot establish whether someone is a human or bot.
    # Only explicit tool-credit footer claims are rejected here; ambiguous
    # names, identity truth and prior bot authorization require human review.
    name, email = identity["name"], identity["email"]
    explicit_tool = re.fullmatch(
        r"(?:claude (?:code|sonnet|opus|haiku)(?: [0-9.]+)?|openai codex|"
        r"chatgpt|github copilot|gemini cli)(?:\[bot\])?", name, re.I)
    generated_pair = (name.casefold(), email.casefold()) in {
        ("claude", "noreply@anthropic.com"), ("copilot", "copilot@github.com")}
    if explicit_tool or generated_pair:
        fail("ai-coauthor-attribution")


def validate_header(header):
    if POLICY is None:
        fail("trusted-policy-unavailable")
    safe_text(header)
    if "\n" in header or len(header) > POLICY["header_width"]:
        fail("header-width-or-line")
    match = re.fullmatch(r"([a-z]+)\((" + POLICY["scope_pattern"] + r")\): (\S(?:.*\S)?)", header)
    if not match or match[1] not in POLICY["types"]:
        fail("scoped-header-required")
    if (match[3].endswith(".") or PLACEHOLDER.fullmatch(match[3])
            or re.search(r"\b(?:fixup|squash|amend)!", match[3], re.I)):
        fail("invalid-subject")


def validate_body(body, *, width=True):
    body = safe_text(body)
    lines = body.split("\n")
    if width and any(len(line) > POLICY["body_width"] for line in lines):
        fail("body-width")
    visible = re.sub(r"<!--[\s\S]*?(?:-->|$)", "", body)
    # Footer continuation lines never become a rationale paragraph.
    rationale = []
    footer = False
    fence = None
    checkbox = False
    quote = False
    paragraph_break = True
    code_block = False
    for raw_line in visible.split("\n"):
        line = raw_line.strip()
        if not line:
            paragraph_break = True
            continue
        if paragraph_break and not raw_line.startswith(" "):
            checkbox = False
            quote = False
        if line.startswith(">"):
            quote = True
        code_block = raw_line.startswith("    ") and (paragraph_break or code_block)
        paragraph_break = False
        marker = re.match(r"^(`{3,}|~{3,})", line)
        if fence is not None:
            if re.fullmatch(re.escape(fence[0]) + "{" + str(len(fence)) + ",}", line):
                fence = None
            continue
        if marker:
            fence = marker[1]
            continue
        if code_block:
            continue
        if PLACEHOLDER.fullmatch(line):
            fail("template-placeholder")
        if TRAILER.match(line):
            footer = True
        if re.match(r"(?:[-*+]|[0-9]+[.)]) \[[ xX]\]", line):
            checkbox = True
        if not footer and not checkbox and not quote and not code_block and not line.startswith(("#", ">")):
            rationale.append(line)
        if line.lower().startswith("co-authored-by:"):
            match = re.fullmatch(r"Co-authored-by: (.+) <([^<>]+)>", line, re.I)
            if not match:
                fail("invalid-coauthor")
            validate_coauthor({"name": match[1], "email": match[2]})
        if line.startswith("BREAKING CHANGE:"):
            if not has_prose(line.partition(":")[2]):
                fail("breaking-impact-required")
    if not has_prose(" ".join(rationale)):
        fail("substantive-rationale-required")


def has_prose(text):
    # Presence only, not a length/language/semantic detector. Human review must
    # decide whether even a concise paragraph actually explains the change.
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"(`+).*?\1", "", text)
    text = re.sub(r"<[^>]*>", "", text)
    return any(character.isalpha() for character in text)


def validate_message(message):
    lines = safe_text(message).split("\n")
    validate_header(lines[0])
    if len(lines) < 3 or lines[1] != "":
        fail("blank-line-required")
    validate_body("\n".join(lines[2:]))


def validate_commit(commit):
    validate_message(commit.message)
    validate_identity(commit.author)
    validate_identity(commit.committer)


def validate_merge_metadata(value):
    if not isinstance(value, dict) or set(value) != {"author", "committer"}:
        fail("merge-identities-required")
    validate_identity(value["author"])
    validate_identity(value["committer"])
