#!/bin/sh
# Bounded update-check transport helper (asg.update-fetch/v1).
#
# Installed immutable versioned package member, invoked only by an explicit
# `update check`. Inputs are public release coordinates only: repository,
# channel, native target, installed version, page or tag/asset. Never a
# history root, catalog path, credential or query.
#
# Supported downloaders: an installed curl, otherwise wget. No Rust compiler,
# Python, Node.js or jq is required. At most three redirects and two retries
# share one 30-second deadline. The response body is written to a helper-owned
# temporary file; stdout carries only the small envelope and never raw
# downloader stderr.
#
# This helper never changes execution policy, quarantines files or edits trust.

set -eu

SCHEMA='asg.update-fetch/v1'

mode=''
repository=''
channel=''
target=''
current_version=''
page=''
tag=''
asset=''

fail() {
    code=$1
    status=$2
    printf '{"schema":"%s","status":"error","error":"%s"}\n' "$SCHEMA" "$code"
    exit "$status"
}

need_value() {
    [ "$#" -ge 2 ] || fail usage 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -Mode|--mode) need_value "$@"; mode=$2; shift 2 ;;
        -Repository|--repository) need_value "$@"; repository=$2; shift 2 ;;
        -Channel|--channel) need_value "$@"; channel=$2; shift 2 ;;
        -Target|--target) need_value "$@"; target=$2; shift 2 ;;
        -CurrentVersion|--current-version) need_value "$@"; current_version=$2; shift 2 ;;
        -Page|--page) need_value "$@"; page=$2; shift 2 ;;
        -Tag|--tag) need_value "$@"; tag=$2; shift 2 ;;
        -Asset|--asset) need_value "$@"; asset=$2; shift 2 ;;
        *) fail usage 2 ;;
    esac
done

valid_token() {
    [ -n "$1" ] && [ "${#1}" -le 200 ] || return 1
    case "$1" in
        *[!A-Za-z0-9._+-]*) return 1 ;;
    esac
    [ "$1" != '.' ] && [ "$1" != '..' ]
}

valid_repository() {
    [ -n "$1" ] && [ "${#1}" -le 200 ] || return 1
    case "$1" in
        *[!A-Za-z0-9._/-]*|/*|*/|*/*/*) return 1 ;;
    esac
    case "$1" in
        */*) ;;
        *) return 1 ;;
    esac
    owner=${1%%/*}
    name=${1#*/}
    [ -n "$owner" ] && [ -n "$name" ] || return 1
    [ "$owner" != '.' ] && [ "$owner" != '..' ] || return 1
    [ "$name" != '.' ] && [ "$name" != '..' ] || return 1
}

# Coarse lexical validation. The Rust caller performs the canonical SemVer
# check; this helper only needs to keep constructed URLs inside safe ASCII.
valid_version() {
    value=$1
    [ -n "$value" ] && [ "${#value}" -le 65 ] || return 1
    case "$value" in
        v*) value=${value#v} ;;
    esac
    [ -n "$value" ] && [ "${#value}" -le 64 ] || return 1
    case "$value" in
        *[!0-9A-Za-z.+-]*) return 1 ;;
    esac
    core=${value%%-*}
    core=${core%%+*}
    case "$core" in
        *.*.*) ;;
        *) return 1 ;;
    esac
    rest=${core#*.}
    case "$rest" in
        *.*.*) return 1 ;;
    esac
    return 0
}

valid_repository "$repository" || fail usage 2

if [ "$mode" = 'page' ]; then
    case "$channel" in
        beta|stable) ;;
        *) fail usage 2 ;;
    esac
    case "$target" in
        x86_64-pc-windows-msvc|x86_64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin) ;;
        *) fail usage 2 ;;
    esac
    valid_version "$current_version" || fail usage 2
    case "$page" in
        1|2|3) ;;
        *) fail usage 2 ;;
    esac
    url="https://api.github.com/repos/$repository/releases?per_page=100&page=$page"
    cap=4194304
elif [ "$mode" = 'asset' ]; then
    case "$tag" in
        v*) ;;
        *) fail usage 2 ;;
    esac
    valid_version "$tag" || fail usage 2
    valid_token "$asset" || fail usage 2
    url="https://github.com/$repository/releases/download/$tag/$asset"
    cap=524288
else
    fail usage 2
fi

if command -v curl >/dev/null 2>&1; then
    downloader='curl'
elif command -v wget >/dev/null 2>&1; then
    downloader='wget'
else
    fail capability 3
fi

start=$(date +%s 2>/dev/null) || fail internal 8

# Sets `remaining` without a command substitution: a failure inside `$(...)`
# would only exit the subshell and could lose the precise error document.
check_time() {
    now=$(date +%s 2>/dev/null) || fail internal 8
    remaining=$((30 - (now - start)))
    [ "$remaining" -gt 0 ] || fail timeout 4
}

tmpdir=${TMPDIR:-/tmp}
make_temp() {
    if command -v mktemp >/dev/null 2>&1; then
        mktemp "$tmpdir/asg-update-check.XXXXXX" 2>/dev/null
    else
        path="$tmpdir/asg-update-check.$$"
        (umask 077; : > "$path") 2>/dev/null || return 1
        printf '%s\n' "$path"
    fi
}

body=''
headers=''
errors=''
body_keep=0
cleanup() {
    [ -n "$headers" ] && rm -f "$headers"
    [ -n "$errors" ] && rm -f "$errors"
    if [ "$body_keep" -eq 0 ] && [ -n "$body" ]; then
        rm -f "$body"
    fi
}
trap cleanup EXIT HUP INT TERM

body=$(make_temp) || fail internal 8
headers=$(make_temp) || fail internal 8
errors=$(make_temp) || fail internal 8

allowed_final_url() {
    case "$1" in
        https://github.com/*|https://objects.githubusercontent.com/*|https://release-assets.githubusercontent.com/*)
            return 0
            ;;
    esac
    return 1
}

allowed_redirect() {
    case "$1" in
        https://github.com/*|https://objects.githubusercontent.com/*|https://release-assets.githubusercontent.com/*)
            return 0
            ;;
    esac
    return 1
}

header_location() {
    # IGNORECASE is a gawk extension; mawk/BSD awk silently treat it as an
    # unset variable, so match header names with an explicit tolower
    # comparison instead.
    awk '{
             if (tolower($0) !~ /^[[:space:]]*location:/) next
             sub(/^[^:]*:[[:space:]]*/, "")
             sub(/\r$/, "")
             print
             exit
         }' "$headers" 2>/dev/null
}

last_locations() {
    awk '{
             if (tolower($0) !~ /^[[:space:]]*location:/) next
             sub(/^[^:]*:[[:space:]]*/, "")
             sub(/\r$/, "")
             print
         }' "$headers" 2>/dev/null
}

# One deadline for every request and retry. A retry never resets it.
if [ "$downloader" = 'curl' ]; then
    current_url=$url
    redirects=0
    retries=0
    final_url=''
    bytes=0
    while :; do
        check_time
        connect=10
        [ "$remaining" -lt "$connect" ] && connect=$remaining
        : > "$headers"
        set +e
        status=$(curl --silent --show-error --proto '=https' --tlsv1.2 \
            --connect-timeout "$connect" --max-time "$remaining" \
            --max-filesize "$cap" --max-redirs 0 \
            --user-agent 'agent-session-grep-update-check' \
            --header 'Accept: application/vnd.github+json' \
            --header 'X-GitHub-Api-Version: 2022-11-28' \
            --dump-header "$headers" --output "$body" \
            --write-out '%{http_code}' "$current_url" 2>"$errors")
        rc=$?
        set -e
        if [ "$rc" -ne 0 ]; then
            [ "$rc" -eq 63 ] && fail too_large 7
            if [ "$retries" -lt 2 ]; then
                check_time
                retries=$((retries + 1))
                sleep 1
                continue
            fi
            [ "$rc" -eq 28 ] && fail timeout 4
            fail network 4
        fi
        case "$status" in
            200)
                bytes=$(wc -c < "$body" 2>/dev/null | tr -d ' ')
                [ -n "$bytes" ] || fail internal 8
                [ "$bytes" -le "$cap" ] || fail too_large 7
                final_url=$current_url
                break
                ;;
            301|302|303|307|308)
                location=$(header_location)
                [ -n "$location" ] || fail redirect_rejected 6
                case "$location" in
                    https://*) ;;
                    *) fail redirect_rejected 6 ;;
                esac
                allowed_redirect "$location" || fail redirect_rejected 6
                redirects=$((redirects + 1))
                [ "$redirects" -le 3 ] || fail redirect_rejected 6
                current_url=$location
                continue
                ;;
            429|500|502|503|504)
                if [ "$retries" -lt 2 ]; then
                    check_time
                    retries=$((retries + 1))
                    sleep 1
                    continue
                fi
                fail http_status 5
                ;;
            000)
                if [ "$retries" -lt 2 ]; then
                    check_time
                    retries=$((retries + 1))
                    sleep 1
                    continue
                fi
                fail network 4
                ;;
            *)
                fail http_status 5
                ;;
        esac
    done
else
    current_url=$url
    retries=0
    final_url=''
    bytes=0
    while :; do
        check_time
        # wget follows redirects internally and downloads along the way, so
        # the allowlist must be enforced on the URL BEFORE each request, not
        # only on the recorded Location headers afterwards.
        allowed_redirect "$current_url" || fail redirect_rejected 6
        : > "$headers"
        set +e
        wget --https-only --max-redirect=3 --tries=1 \
            --connect-timeout=10 --timeout="$remaining" \
            --user-agent='agent-session-grep-update-check' \
            --header='Accept: application/vnd.github+json' \
            -S -O "$body" "$current_url" 2>"$headers"
        rc=$?
        set -e
        if [ "$rc" -eq 0 ]; then
            bytes=$(wc -c < "$body" 2>/dev/null | tr -d ' ')
            [ -n "$bytes" ] || fail internal 8
            [ "$bytes" -le "$cap" ] || fail too_large 7
            final_url=$current_url
            old_ifs=$IFS
            IFS='
'
            for location in $(last_locations); do
                allowed_redirect "$location" || fail redirect_rejected 6
                final_url=$location
            done
            IFS=$old_ifs
            break
        fi
        if [ "$retries" -lt 2 ]; then
            check_time
            retries=$((retries + 1))
            sleep 1
            continue
        fi
        [ "$rc" -eq 4 ] && fail network 4
        [ "$rc" -eq 28 ] && fail timeout 4
        fail http_status 5
    done
fi

if [ "$mode" = 'page' ] && [ "$final_url" != "$url" ]; then
    fail redirect_rejected 6
fi
if [ "$mode" = 'asset' ]; then
    allowed_final_url "$final_url" || fail redirect_rejected 6
fi

case "$final_url" in
    *'"'*|*\\*) fail internal 8 ;;
esac
case "$body" in
    *'"'*|*\\*) fail internal 8 ;;
esac

body_keep=1
printf '{"schema":"%s","status":"ok","url":"%s","bytes":%s,"file":"%s"}\n' \
    "$SCHEMA" "$final_url" "$bytes" "$body"
exit 0
