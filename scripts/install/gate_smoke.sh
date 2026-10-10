#!/usr/bin/env bash
# Local install gate: install -> smoke both commands -> upgrade in place ->
# uninstall twice -> reinstall -> smoke -> final uninstall, all against a
# throwaway prefix.

set -euo pipefail

prefix=""
binary=""
output_dir=""

fail() {
    printf 'gate: error: %s\n' "$1" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: gate_smoke.sh [--prefix <dir>] [--binary <path>] [--output-dir <dir>]

  --prefix <dir>     install directory (default: ${XDG_BIN_HOME:-$HOME/.local/bin})
  --binary <path>    prebuilt release binary; install runs with --skip-build
  --output-dir <dir> gate evidence output (default: scripts/evidence/out)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            [ $# -ge 2 ] || fail '--prefix requires a directory'
            prefix="$2"
            shift 2
            ;;
        --binary)
            [ $# -ge 2 ] || fail '--binary requires a path'
            binary="$2"
            shift 2
            ;;
        --output-dir)
            [ $# -ge 2 ] || fail '--output-dir requires a directory'
            output_dir="$2"
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

if [ -z "$output_dir" ]; then
    output_dir="$repo_root/scripts/evidence/out"
fi
mkdir -p "$output_dir"

install="$script_dir/install.sh"
smoke="$script_dir/smoke.sh"
uninstall="$script_dir/uninstall.sh"
for script in "$install" "$smoke" "$uninstall"; do
    [ -f "$script" ] || fail "missing script: $script"
done

steps=""
failures=0

record() {
    local name="$1" ok="$2" detail="$3"
    if [ "$ok" -eq 0 ]; then
        printf 'gate: pass  %s\n' "$name"
    else
        failures=$((failures + 1))
        printf 'gate: FAIL  %s\n' "$name" >&2
        [ -n "$detail" ] && printf 'gate:       %s\n' "$detail" >&2
    fi
    steps="$steps{\"name\":\"$name\",\"ok\":$([ "$ok" -eq 0 ] && echo true || echo false),\"detail\":\"$detail\"},"
}

install_args=()
if [ -n "$prefix" ]; then
    install_args+=(--prefix "$prefix")
fi
if [ -n "$binary" ]; then
    [ -f "$binary" ] || fail "binary not found: $binary"
    # install.sh --skip-build copies target/release/agent-session-grep, so a
    # caller-supplied binary is staged into target/release first. --binary is
    # commonly the repo artifact itself, and `cp` refuses a same-file copy, so
    # a destination that already holds those bytes skips the copy.
    mkdir -p "$repo_root/target/release"
    repo_artifact="$repo_root/target/release/agent-session-grep"
    if [ -f "$repo_artifact" ] && cmp -s "$binary" "$repo_artifact"; then
        printf 'gate: binary already matches the repo artifact; skipping staging copy\n'
    else
        cp -f "$binary" "$repo_artifact" || fail "cannot stage binary into $repo_artifact"
    fi
    install_args+=(--skip-build)
fi

# 1. install (build, or skip-build with an explicit binary).
set +e
"$install" "${install_args[@]}"
code=$?
set -e
record 'install' "$([ "$code" -eq 0 ] && echo 0 || echo 1)" "exit=$code"

# 2. smoke against the installed binary. Prefix resolution mirrors install.sh.
if [ -z "$prefix" ]; then
    if [ -n "${XDG_BIN_HOME:-}" ]; then
        prefix="$XDG_BIN_HOME"
    elif [ -n "${HOME:-}" ]; then
        prefix="$HOME/.local/bin"
    else
        fail 'neither XDG_BIN_HOME nor HOME is set; pass --prefix <dir>'
    fi
fi
installed="$prefix/agent-session-grep"
installed_alias="$prefix/asg"

run_smoke() {
    local label="$1"
    set +e
    "$smoke" --binary "$installed" --alias-binary "$installed_alias"
    code=$?
    set -e
    record "$label" "$([ "$code" -eq 0 ] && echo 0 || echo 1)" "exit=$code"
}

if [ -f "$installed" ] && { [ -f "$installed_alias" ] || [ -L "$installed_alias" ]; }; then
    run_smoke 'smoke-installed'
else
    record 'smoke-installed' 1 "installed commands not found at $installed and $installed_alias"
fi

# 3. Upgrade in place while both managed commands already exist.
set +e
"$install" "${install_args[@]}"
code=$?
set -e
record 'upgrade' "$([ "$code" -eq 0 ] && echo 0 || echo 1)" "exit=$code"
if [ -f "$installed" ] && { [ -f "$installed_alias" ] || [ -L "$installed_alias" ]; }; then
    run_smoke 'smoke-upgraded'
else
    record 'smoke-upgraded' 1 "upgraded commands not found at $installed and $installed_alias"
fi

# 4. Uninstall both managed commands.
set +e
"$uninstall" --prefix "$prefix"
code=$?
set -e
record 'uninstall' "$([ "$code" -eq 0 ] && echo 0 || echo 1)" "exit=$code"
if { [ ! -e "$installed" ] && [ ! -L "$installed" ]; } && \
   { [ ! -e "$installed_alias" ] && [ ! -L "$installed_alias" ]; }; then
    record 'uninstall-files-removed' 0 ''
else
    record 'uninstall-files-removed' 1 "canonical=$installed alias=$installed_alias"
fi

# 5. Uninstall again: second run reports "not installed" and exits 0.
set +e
"$uninstall" --prefix "$prefix"
code=$?
set -e
record 'uninstall-idempotent' "$([ "$code" -eq 0 ] && echo 0 || echo 1)" "exit=$code"

# 6. Reinstall after a clean uninstall.
set +e
"$install" "${install_args[@]}"
code=$?
set -e
record 'reinstall' "$([ "$code" -eq 0 ] && echo 0 || echo 1)" "exit=$code"

# 7. Smoke against both reinstalled commands.
if [ -f "$installed" ] && { [ -f "$installed_alias" ] || [ -L "$installed_alias" ]; }; then
    run_smoke 'smoke-reinstalled'
else
    record 'smoke-reinstalled' 1 "reinstalled commands not found at $installed and $installed_alias"
fi

# 8. Final uninstall leaves both managed paths absent.
set +e
"$uninstall" --prefix "$prefix"
code=$?
set -e
record 'uninstall-final' "$([ "$code" -eq 0 ] && echo 0 || echo 1)" "exit=$code"
if { [ ! -e "$installed" ] && [ ! -L "$installed" ]; } && \
   { [ ! -e "$installed_alias" ] && [ ! -L "$installed_alias" ]; }; then
    record 'uninstall-final-files-removed' 0 ''
else
    record 'uninstall-final-files-removed' 1 "canonical=$installed alias=$installed_alias"
fi

steps="${steps%,}"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$os" = "darwin" ]; then os="macos"; fi
[ "$failures" -eq 0 ] && gate_pass=true || gate_pass=false

cat > "$output_dir/install-gate-$os.json" <<EOF
{
  "schema_version": "agent-session-grep.install-gate/v1",
  "os": "$os",
  "pass": $gate_pass,
  "failures": $failures,
  "steps": [$steps],
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
printf 'gate: manifest %s\n' "$output_dir/install-gate-$os.json"

if [ "$failures" -gt 0 ]; then
    printf 'gate: %d step(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'gate: all install-gate steps passed\n'
exit 0
