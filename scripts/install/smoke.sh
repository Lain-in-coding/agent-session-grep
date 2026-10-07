#!/usr/bin/env bash
# Drive every outward surface of an ALREADY-BUILT agent-session-grep binary against a
# throwaway data root seeded with a synthetic fixture. This script never builds:
# building is the job of install.sh or CI, and a smoke run that could rebuild
# would let a stale artifact pass as a fresh one.
#
# The assertion set is kept identical to smoke.ps1 so the three-OS CI matrix
# produces comparable results.

set -euo pipefail

binary=""
alias_binary=""

fail() {
    printf 'smoke: error: %s\n' "$1" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: smoke.sh [--binary <path>] [--alias-binary <path>]

  --binary <path>        binary under test (default: target/release/agent-session-grep)
  --alias-binary <path>  installed asg alias; checks version parity before smoke
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --binary)
            [ $# -ge 2 ] || fail '--binary requires a path'
            binary="$2"
            shift 2
            ;;
        --alias-binary)
            [ $# -ge 2 ] || fail '--alias-binary requires a path'
            alias_binary="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown argument: $1"
            ;;
    esac
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

if [ -z "$binary" ]; then
    binary="$repo_root/target/release/agent-session-grep"
fi
[ -f "$binary" ] || \
    fail "binary not found: $binary (this script does not build; run install.sh or cargo build --locked --release -p agent-session-grep-cli first)"

if [ -n "$alias_binary" ]; then
    [ -f "$alias_binary" ] || [ -L "$alias_binary" ] || fail "alias binary not found: $alias_binary"
    canonical_version=$("$binary" --version) || fail "agent-session-grep --version failed"
    alias_version=$("$alias_binary" --version) || fail "asg --version failed"
    [ "$canonical_version" = "$alias_version" ] || \
        fail "agent-session-grep and asg reported different versions"
    printf 'smoke: ok alias version parity (%s)\n' "$canonical_version"
fi

command -v python3 >/dev/null 2>&1 || \
    fail 'python3 not found on PATH; it is required to parse robot envelopes'

workdir=$(mktemp -d 2>/dev/null || mktemp -d -t agent-session-grep-smoke)
db="$workdir/smoke.db"
fixture="$workdir/synthetic-session.jsonl"

# Diagnostics print before cleanup so a failure is still readable, but the
# throwaway data root is removed on every exit path.
cleanup() {
    rm -rf "$workdir"
}
trap cleanup EXIT

step=0
pass() {
    step=$((step + 1))
    printf 'smoke: ok %02d %s\n' "$step" "$1"
}

# Synthetic Claude Code transcript: root -> reply -> sidechain probe. Entirely
# invented content; no real user data is read at any point.
cat > "$fixture" <<'EOF'
{"type":"user","uuid":"11111111-1111-4111-8111-111111111111","parentUuid":null,"sessionId":"smoke-session-0001","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"zqxjkbrw smoke probe alpha"}}
{"type":"assistant","uuid":"22222222-2222-4222-8222-222222222222","parentUuid":"11111111-1111-4111-8111-111111111111","sessionId":"smoke-session-0001","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"text","text":"zqxjkbrw smoke reply beta"}]}}
{"type":"assistant","uuid":"33333333-3333-4333-8333-333333333333","parentUuid":"22222222-2222-4222-8222-222222222222","sessionId":"smoke-session-0001","isSidechain":true,"timestamp":"2026-01-01T00:00:02.000Z","message":{"role":"assistant","content":"zqxjkbrw smoke sidechain gamma"}}
EOF

# The searchable token is nonsense on purpose: it cannot collide with anything
# already in a store if someone points --binary at a shared checkout.
term='zqxjkbrw'

# Run the binary in robot mode and capture stdout plus the real exit code
# without letting set -e abort before we can assert on the code.
run_robot() {
    set +e
    robot_stdout=$("$binary" --db "$db" --robot "$@" 2>"$workdir/stderr.txt")
    robot_exit=$?
    set -e
    robot_stderr=$(cat "$workdir/stderr.txt")
}

# Assert on a captured envelope via python3: --robot emits exactly one JSON
# object, and each check is a python expression over it. No jq dependency.
assert_envelope() {
    local label="$1" expected_exit="$2"
    shift 2
    if [ "$robot_exit" -ne "$expected_exit" ]; then
        printf 'smoke: %s: expected exit %s, got %s\n' "$label" "$expected_exit" "$robot_exit" >&2
        printf 'smoke: stdout: %s\n' "$robot_stdout" >&2
        printf 'smoke: stderr: %s\n' "$robot_stderr" >&2
        exit 1
    fi
    local check
    for check in "$@"; do
        if ! printf '%s' "$robot_stdout" | python3 -c '
import json, sys
check = sys.argv[1]
raw = sys.stdin.read().strip()
try:
    frame = json.loads(raw)
except Exception as error:
    print(f"envelope is not valid JSON: {error}", file=sys.stderr)
    sys.exit(1)
sys.exit(0 if eval(check, {"isinstance": isinstance, "len": len, "int": int}, {"f": frame}) else 1)
' "$check"; then
            printf 'smoke: %s: assertion failed: %s\n' "$label" "$check" >&2
            printf 'smoke: stdout: %s\n' "$robot_stdout" >&2
            exit 1
        fi
    done
}

# Read one value out of the captured envelope, for ids that must come from real
# output rather than being hardcoded.
envelope_value() {
    printf '%s' "$robot_stdout" | python3 -c '
import json, sys
frame = json.load(sys.stdin)
value = eval(sys.argv[1], {"__builtins__": {}}, {"f": frame})
if value is None or value == "":
    print("extracted an empty value", file=sys.stderr)
    sys.exit(1)
print(value)
' "$1"
}

# 1. doctor on a fresh store: opening it creates and migrates the schema.
#    run_robot already prepends --db "$db" --robot; passing --db again here
#    yields a duplicate flag and fails the first smoke step.
run_robot doctor
assert_envelope 'doctor' 0 \
    'f["ok"] is True' \
    'f["data"]["db"] == "ok"' \
    'isinstance(f["data"]["schema"], int)'
pass 'doctor reports db ok with a numeric schema'

# 2. sync the synthetic fixture: all three conversational records must land.
run_robot sync "$fixture"
assert_envelope 'sync' 0 \
    'f["ok"] is True' \
    'f["data"]["messages"] == 3'
pass 'sync ingested 3 messages from the synthetic fixture'

# 3. search for the fixture token; hits are message-level entities.
run_robot search "$term"
assert_envelope 'search' 0 \
    'f["ok"] is True' \
    'len(f["data"]["hits"]) > 0' \
    'f["data"]["hits"][0]["id"].startswith("msg_v1_")'
pass 'search returned msg_v1_ hits for the fixture term'
hit_id=$(envelope_value 'f["data"]["hits"][0]["id"]')

# 4. context needs the session id discovered from real output, never a
#    hardcoded one: the id derives from the provider-native sessionId.
run_robot list 50
assert_envelope 'list' 0 'f["ok"] is True'
session_id=$(envelope_value '[e["id"] for e in f["data"]["entries"] if e["id"].startswith("ses_v1_")][0]')

run_robot context "$session_id"
assert_envelope 'context' 0 \
    'f["ok"] is True' \
    'len(f["data"]["messages"]) > 0' \
    'len(f["data"]["evidence"]) > 0'
pass "context assembled messages and evidence for $session_id"
anchor_id=$(envelope_value 'f["data"]["messages"][0]["message_id"]')

# 5. catalog holds 3 messages + 1 session + 1 document.
run_robot status
assert_envelope 'status' 0 \
    'f["ok"] is True' \
    'f["data"]["catalog_count"] >= 5'
pass 'status reports at least 5 catalog entities'

# 6. get the id search just returned.
run_robot get "$hit_id"
assert_envelope 'get' 0 \
    'f["ok"] is True' \
    'f["data"]["payload"]'
pass 'get returned a non-empty payload for the search hit'

# 7. A well-formed but absent id is not_found: exit 4 with ok:false and
#    error.code not_found (ADR-0005; the message is generic and never echoes
#    the wire id).
run_robot get 'ses_v1_nope'
assert_envelope 'get-absent' 4 \
    'f["ok"] is False' \
    'f["error"]["code"] == "not_found"'
pass 'absent id yields exit 4 with error.code not_found'

# 8. context on an absent session carries the same not_found contract.
run_robot context 'ses_v1_ffffffff-ffff-4fff-8fff-ffffffffffff'
assert_envelope 'not-found' 4 \
    'f["ok"] is False' \
    'f["error"]["code"] == "not_found"'
pass 'absent session yields exit 4 with error.code not_found'

# 8. a garbage continuation token is a request error, not a silent empty page.
run_robot search "$term" --cursor garbage
assert_envelope 'cursor-invalid' 2 \
    'f["ok"] is False' \
    'f["error"]["code"] == "cursor_invalid"'
pass 'garbage cursor yields exit 2 with error.code cursor_invalid'

# 9. MCP stdio handshake: stdout must carry nothing but JSON-RPC frames, and
#    EOF on stdin must shut the server down cleanly.
mcp_in="$workdir/mcp-in.jsonl"
mcp_out="$workdir/mcp-out.jsonl"
cat > "$mcp_in" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_status","arguments":{}}}
EOF
printf '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_message","arguments":{"message_id":"%s","session_id":"%s","around":0}}}\n' \
    "$anchor_id" "$session_id" >> "$mcp_in"

set +e
"$binary" --db "$db" mcp <"$mcp_in" >"$mcp_out" 2>"$workdir/mcp-stderr.txt"
mcp_exit=$?
set -e
if [ "$mcp_exit" -ne 0 ]; then
    printf 'smoke: mcp: expected exit 0, got %s\n' "$mcp_exit" >&2
    cat "$mcp_out" >&2
    cat "$workdir/mcp-stderr.txt" >&2
    exit 1
fi

if ! python3 -c '
import json, sys
frames = []
with open(sys.argv[1], encoding="utf-8") as handle:
    for number, line in enumerate(handle, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            frames.append(json.loads(line))
        except Exception as error:
            print(f"stdout line {number} is not valid JSON: {error}", file=sys.stderr)
            sys.exit(1)

by_id = {frame.get("id"): frame for frame in frames}
for expected in (1, 2, 3, 4):
    if expected not in by_id:
        print(f"missing JSON-RPC response for id {expected}", file=sys.stderr)
        sys.exit(1)

listed = by_id[2].get("result", {}).get("tools")
if not isinstance(listed, list) or len(listed) != 9:
    count = len(listed) if isinstance(listed, list) else "absent"
    print(f"tools/list must report exactly 9 tools, got {count}", file=sys.stderr)
    sys.exit(1)

called = by_id[3].get("result", {})
flag = called.get("isError")
if flag is not False:
    print(f"tools/call get_status must report isError false, got {flag!r}", file=sys.stderr)
    sys.exit(1)

message_result = by_id[4].get("result", {})
if message_result.get("isError") is not False:
    print("tools/call get_message must report isError false", file=sys.stderr)
    sys.exit(1)
message_data = message_result.get("structuredContent", {}).get("data", {})
if message_data.get("message_id") != sys.argv[2]:
    print("get_message did not return the requested real message id", file=sys.stderr)
    sys.exit(1)
if len(message_data.get("messages", [])) != 1:
    print("get_message around=0 must return exactly one message", file=sys.stderr)
    sys.exit(1)
' "$mcp_out" "$anchor_id"; then
    printf 'smoke: mcp: handshake assertions failed\n' >&2
    cat "$mcp_out" >&2
    exit 1
fi
pass 'MCP stdio handshake: 9 tools listed, get_status and get_message succeeded'

printf 'smoke: all %d assertions passed against %s\n' "$step" "$binary"
exit 0
