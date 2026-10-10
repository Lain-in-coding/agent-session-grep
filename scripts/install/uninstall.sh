#!/usr/bin/env bash
# Remove the two commands installed by install.sh.
#
# Deletes only agent-session-grep and its managed asg alias. It never removes a
# directory recursively or touches a data root. Missing files are success, so
# normal repeated runs are safe.

set -euo pipefail

fail() {
    printf 'uninstall: error: %s\n' "$1" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: uninstall.sh [--prefix <dir>]

  --prefix <dir>  install directory (default: ${XDG_BIN_HOME:-$HOME/.local/bin})
EOF
}

prefix=""

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            [ $# -ge 2 ] || fail '--prefix requires a directory'
            prefix="$2"
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

binary_name="agent-session-grep"
alias_name="asg"
wrapper_marker="# agent-session-grep managed asg wrapper"

if [ -z "$prefix" ]; then
    if [ -n "${XDG_BIN_HOME:-}" ]; then
        prefix="$XDG_BIN_HOME"
    elif [ -n "${HOME:-}" ]; then
        prefix="$HOME/.local/bin"
    else
        fail 'neither XDG_BIN_HOME nor HOME is set; pass --prefix <dir>'
    fi
fi

installed_binary="$prefix/$binary_name"
installed_alias="$prefix/$alias_name"

alias_is_managed() {
    if [ -L "$installed_alias" ]; then
        alias_link=$(readlink "$installed_alias") || return 1
        [ "$alias_link" = "$binary_name" ] || [ "$alias_link" = "$installed_binary" ]
    elif [ -f "$installed_alias" ]; then
        [ "$(sed -n '2p' "$installed_alias")" = "$wrapper_marker" ] || \
            { [ -f "$installed_binary" ] && cmp -s "$installed_alias" "$installed_binary"; }
    else
        return 1
    fi
}

binary_exists=0
alias_exists=0
[ -e "$installed_binary" ] || [ -L "$installed_binary" ] || binary_exists=1
[ -e "$installed_alias" ] || [ -L "$installed_alias" ] || alias_exists=1

if [ "$binary_exists" -ne 0 ] && [ "$alias_exists" -ne 0 ]; then
    printf 'not installed: %s or %s\n' "$installed_binary" "$installed_alias"
    exit 0
fi

# Fail before deleting either path if asg is no longer recognizable as the
# managed alias. This protects unrelated files in a custom shared prefix.
if [ "$alias_exists" -eq 0 ] && ! alias_is_managed; then
    fail "$installed_alias is not a managed agent-session-grep alias; refusing to remove either file"
fi

if [ "$alias_exists" -eq 0 ]; then
    rm -f "$installed_alias" || fail "cannot remove $installed_alias"
    printf 'removed: %s\n' "$installed_alias"
fi
if [ "$binary_exists" -eq 0 ]; then
    rm -f "$installed_binary" || fail "cannot remove $installed_binary"
    printf 'removed: %s\n' "$installed_binary"
fi
printf '\n'
printf 'Your config, data, cache, and logs were not touched. To remove those,\n'
printf 'delete the paths reported by: agent-session-grep --robot config paths\n'
