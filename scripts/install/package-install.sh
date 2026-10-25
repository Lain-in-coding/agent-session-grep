#!/bin/sh
# Offline first-install foundation. Requires POSIX sh and common Unix tools.
set -eu
LC_ALL=C
export LC_ALL
umask 077
fail() { printf '%s\n' "package-install: $*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: sh package-install.sh --manifest FILE --checksums FILE [--prefix DIR] [--host claude|codex|workbuddy|zcode|deepseek-harness|antigravity]... [--claude-history DIR] [--codex-history DIR] [--workbuddy-history DIR] [--zcode-history DIR] [--deepseek-harness-history DIR] [--antigravity-history DIR] [--catalog FILE] [--no-autostart] [--no-path]'
    exit 0
}
option_value() {
    [ "$1" -ge 2 ] && [ -n "$2" ] || fail 'missing option value'
    case $2 in --*|-h) fail 'missing option value' ;; *[![:space:]]*) ;; *) fail 'empty option value' ;; esac
}
manifest= checksums= prefix= stage= probe_pid= watchdog=
selected_count=0 selected_claude=0 selected_codex=0 selected_workbuddy=0 selected_zcode=0 selected_dsh=0 selected_antigravity=0
claude_history= codex_history= workbuddy_history= zcode_history= dsh_history= antigravity_history= catalog= no_autostart=0 no_path=0
while [ "$#" -gt 0 ]; do
    case $1 in
        --help|-h) usage ;;
        --host)
            option_value "$#" "${2-}"
            case $2 in
                claude) [ "$selected_claude" = 0 ] || fail 'duplicate host'; selected_claude=1 ;;
                codex) [ "$selected_codex" = 0 ] || fail 'duplicate host'; selected_codex=1 ;;
                workbuddy) [ "$selected_workbuddy" = 0 ] || fail 'duplicate host'; selected_workbuddy=1 ;;
                zcode) [ "$selected_zcode" = 0 ] || fail 'duplicate host'; selected_zcode=1 ;;
                deepseek-harness) [ "$selected_dsh" = 0 ] || fail 'duplicate host'; selected_dsh=1 ;;
                antigravity) [ "$selected_antigravity" = 0 ] || fail 'duplicate host'; selected_antigravity=1 ;;
                *) fail 'unsupported host' ;;
            esac
            selected_count=$((selected_count + 1))
            shift 2 ;;
        --claude-history|--codex-history|--workbuddy-history|--zcode-history|--deepseek-harness-history|--antigravity-history|--catalog)
            option_value "$#" "${2-}"
            case $1 in
                *-history) case $2 in -*) fail 'history option value cannot start with a flag' ;; esac ;;
            esac
            case $1 in
                --claude-history) [ -z "$claude_history" ] || fail 'duplicate history'; claude_history=$2 ;;
                --codex-history) [ -z "$codex_history" ] || fail 'duplicate history'; codex_history=$2 ;;
                --workbuddy-history) [ -z "$workbuddy_history" ] || fail 'duplicate history'; workbuddy_history=$2 ;;
                --zcode-history) [ -z "$zcode_history" ] || fail 'duplicate history'; zcode_history=$2 ;;
                --deepseek-harness-history) [ -z "$dsh_history" ] || fail 'duplicate history'; dsh_history=$2 ;;
                --antigravity-history) [ -z "$antigravity_history" ] || fail 'duplicate history'; antigravity_history=$2 ;;
                --catalog) [ -z "$catalog" ] || fail 'duplicate catalog'; catalog=$2 ;;
            esac
            shift 2 ;;
        --no-autostart) [ "$no_autostart" = 0 ] || fail 'duplicate option'; no_autostart=1; shift ;;
        --no-path) [ "$no_path" = 0 ] || fail 'duplicate option'; no_path=1; shift ;;
        --manifest|--checksums|--prefix)
            option_value "$#" "${2-}"
            case $1 in
                --manifest) [ -z "$manifest" ] || fail 'duplicate manifest'; manifest=$2 ;;
                --checksums) [ -z "$checksums" ] || fail 'duplicate checksums'; checksums=$2 ;;
                --prefix) [ -z "$prefix" ] || fail 'duplicate prefix'; prefix=$2 ;;
            esac
            shift 2 ;;
        *) fail 'unknown option' ;;
    esac
done
[ -n "$manifest" ] && [ -n "$checksums" ] || fail 'manifest and SHA256SUMS are required'
[ -z "$claude_history" ] || [ "$selected_claude" = 1 ] || fail 'Claude history requires --host claude'
[ -z "$codex_history" ] || [ "$selected_codex" = 1 ] || fail 'Codex history requires --host codex'
[ -z "$workbuddy_history" ] || [ "$selected_workbuddy" = 1 ] || fail 'WorkBuddy history requires --host workbuddy'
[ -z "$zcode_history" ] || [ "$selected_zcode" = 1 ] || fail 'ZCode history requires --host zcode'
[ -z "$dsh_history" ] || [ "$selected_dsh" = 1 ] || fail 'DeepSeek Harness history requires --host deepseek-harness'
[ -z "$antigravity_history" ] || [ "$selected_antigravity" = 1 ] || fail 'Antigravity history requires --host antigravity'
if [ "$selected_count" = 0 ]; then
    [ -z "$catalog" ] && [ "$no_autostart" = 0 ] && [ "$no_path" = 0 ] || fail 'setup options require explicit --host'
fi

complete_selected_setup() {
    if [ "$selected_count" = 0 ]; then
        printf '%s\n' 'Select assistants and explicit history with --host and the matching --claude-history/--codex-history/--workbuddy-history/--zcode-history/--deepseek-harness-history/--antigravity-history option.'
        return
    fi
    set -- --robot
    [ -z "$catalog" ] || set -- "$@" --db "$catalog"
    set -- "$@" setup --install-prefix "$prefix"
    [ "$selected_claude" = 0 ] || set -- "$@" --host claude
    [ "$selected_codex" = 0 ] || set -- "$@" --host codex
    [ "$selected_workbuddy" = 0 ] || set -- "$@" --host workbuddy
    [ "$selected_zcode" = 0 ] || set -- "$@" --host zcode
    [ "$selected_dsh" = 0 ] || set -- "$@" --host deepseek-harness
    [ "$selected_antigravity" = 0 ] || set -- "$@" --host antigravity
    [ -z "$claude_history" ] || set -- "$@" --history claude-code "$claude_history"
    [ -z "$codex_history" ] || set -- "$@" --history codex "$codex_history"
    [ -z "$workbuddy_history" ] || set -- "$@" --history workbuddy "$workbuddy_history"
    [ -z "$zcode_history" ] || set -- "$@" --history zcode "$zcode_history"
    [ -z "$dsh_history" ] || set -- "$@" --history deepseek-harness "$dsh_history"
    [ -z "$antigravity_history" ] || set -- "$@" --history antigravity "$antigravity_history"
    [ "$no_autostart" = 0 ] || set -- "$@" --no-autostart
    setup_exit=0
    "$prefix/agent-session-grep" "$@" || setup_exit=$?
    case $setup_exit in 0|10) ;; *) fail 'package installed; selected setup failed, durable stages retained' ;; esac
    if [ "$no_path" = 0 ]; then
        set -- --robot
        [ -z "$catalog" ] || set -- "$@" --db "$catalog"
        path_exit=0
        "$prefix/agent-session-grep" "$@" path install --install-prefix "$prefix" || path_exit=$?
        case $path_exit in 0|10) ;; *) fail 'package/setup retained; user PATH registration incomplete' ;; esac
    fi
    printf '%s\n' 'package-install: selected setup recorded; host/model loading and native login remain separately reported.'
}

plain_path() {
    case $1 in /*) ;; *) fail 'absolute paths required internally' ;; esac
    pp=$1
    while [ "$pp" != / ]; do
        [ ! -L "$pp" ] || fail 'symlink path is not supported'
        pp=${pp%/*}; [ -n "$pp" ] || pp=/
    done
}
absolute() {
    case $1 in /*) raw_path=$1 ;; *) raw_path=$PWD/$1 ;; esac
    # Check the lexical ancestors before collapsing dots; link/../ must not
    # hide traversal through a symlink. Then normalize without following links.
    plain_path "$raw_path"
    printf '%s\n' "$raw_path" | awk -F / '
        NR!=1 {exit 1}
        {for(i=1;i<=NF;i++) {
            if($i=="" || $i==".") continue
            if($i=="..") {if(n>0) n--; continue}
            a[++n]=$i
        }}
        END {printf "/"; for(i=1;i<=n;i++) printf "%s%s",a[i],(i<n?"/":""); printf "\n"}
    '
}
regular() { plain_path "$1"; [ -f "$1" ] || fail 'required regular file missing'; }
safe_relative() {
    printf '%s\n' "$1" | awk '
        !/^[A-Za-z0-9][A-Za-z0-9_.+\/-]*$/ {exit 1}
        {n=split($0,a,"/"); for(i=1;i<=n;i++)
            if(a[i] !~ /^[A-Za-z0-9][A-Za-z0-9_.+-]*$/ || a[i] ~ /\.$/ ||
               toupper(a[i]) ~ /^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$)/) exit 1}
    ' || fail 'unsafe package path'
}
if command -v sha256sum >/dev/null 2>&1; then sha_kind=sha256sum
elif command -v shasum >/dev/null 2>&1; then sha_kind=shasum
elif command -v sha256 >/dev/null 2>&1; then sha_kind=sha256
else fail 'a SHA256 utility (sha256sum, shasum or sha256) is required'; fi
digest() {
    regular "$1"
    case $sha_kind in
        sha256sum) dh=$(sha256sum < "$1") ;;
        shasum) dh=$(shasum -a 256 < "$1") ;;
        sha256) dh=$(sha256 -q < "$1") ;;
    esac
    printf '%s\n' "${dh%% *}"
}
json_string() {
    # Only the canonical builder's single-line scalar subset is accepted.
    # Duplicate keys and escapes are rejected, never evaluated as shell code.
    awk -v key="$2" '
        $0 ~ "^[ ]*\"" key "\": \"[A-Za-z0-9_.+:/-]+\"[,]?$" {
            line=$0; sub(/^[ ]*"[^"]+": "/,"",line); sub(/"[,]?$/,"",line); value=line; n++
        }
        END {if(n!=1) exit 1; print value}
    ' "$1" || fail 'invalid or ambiguous manifest scalar'
}
checksum_for() {
    awk -v key="$1" '$2==key {value=$1;n++} END {if(n!=1) exit 1; print value}' "$checksums" || fail 'missing checksum'
}
manifest=$(absolute "$manifest"); checksums=$(absolute "$checksums")
regular "$manifest"; regular "$checksums"
[ "$(wc -c < "$manifest" | tr -d ' ')" -le 524288 ] || fail 'manifest exceeds size limit'
[ "$(wc -c < "$checksums" | tr -d ' ')" -le 262144 ] || fail 'checksums exceed size limit'
awk '
    length($1)!=64 || $1 ~ /[^0-9a-f]/ || $0 !~ /^[0-9a-f]+  [A-Za-z0-9][A-Za-z0-9_.+-]*$/ {exit 1}
    seen[tolower($2)]++ || NR>16 {exit 1}
' "$checksums" || fail 'invalid or duplicate SHA256SUMS entry'
manifest_hash=$(digest "$manifest")
[ "$(checksum_for "${manifest##*/}")" = "$manifest_hash" ] || fail 'manifest checksum mismatch'
[ "$(json_string "$manifest" layout)" = asg.managed-candidate/v1 ] || fail 'unsupported package layout'
[ "$(json_string "$manifest" schema)" = agent-session-grep.release-archive-manifest/v1 ] || fail 'unsupported manifest schema'
files_hash=$(json_string "$manifest" install_manifest_sha256)

script=$(absolute "$0"); regular "$script"
root=${script%/*}
files=$root/PACKAGE-MANIFEST.tsv
[ "$(digest "$files")" = "$files_hash" ] || fail 'package file manifest checksum mismatch'
tab=$(printf '\t')
awk -F '\t' '
    NR==1 {if($0!="asg.package-files/v1") exit 1; next}
    $1=="file" {
        if(NF!=5 || length($2)!=64 || $2 ~ /[^0-9a-f]/ || ($3!="0644" && $3!="0755") || $4 !~ /^[0-9]+$/ || seen[tolower($5)]++) exit 1
        next
    }
    NF!=2 || !($1 ~ /^(version|target|source_commit|app|app_sha256|dir|supervisor|supervisor_sha256|launcher_protocol|catalog_schema|control_schema|built_at)$/) || meta[$1]++ {exit 1}
    END {for(key in meta) n++; if(n!=12) exit 1}
' "$files" || fail 'invalid package file manifest'
field() { awk -F '\t' -v key="$1" '$1==key {print $2}' "$files"; }
version=$(field version); target=$(field target); commit=$(field source_commit)
app=$(field app); app_hash=$(field app_sha256); dir=$(field dir)
supervisor=$(field supervisor); supervisor_hash=$(field supervisor_sha256)
safe_relative "$version"; safe_relative "$dir"
printf '%s\n' "$commit" "$app_hash" "$files_hash" "$supervisor_hash" | awk '
    NR==1 {if(length($0)!=40 || /[^0-9a-f]/) exit 1; next}
    length($0)!=64 || /[^0-9a-f]/ {exit 1}
' || fail 'invalid identity digest'
for schema in "$(field catalog_schema)" "$(field control_schema)"; do
    printf '%s\n' "$schema" | awk '!/^[1-9][0-9]*$/ || $0+0>4294967295 {exit 1}' || fail 'invalid schema number'
done
[ "$app" = agent-session-grep ] || fail 'wrong application name'
[ "$supervisor" = asg-supervisor ] || fail 'wrong supervisor name'
[ "$dir" = "versions/$version-$(printf '%.12s' "$app_hash")" ] || fail 'invalid version directory'
[ "$(field launcher_protocol)" = 1 ] || fail 'unsupported launcher protocol'
case $(uname -s):$(uname -m) in
    Linux:x86_64) host=x86_64-unknown-linux-gnu ;;
    Darwin:x86_64) host=x86_64-apple-darwin ;;
    Darwin:arm64) host=aarch64-apple-darwin ;;
    *) fail 'unsupported native target' ;;
esac
[ "$host" = "$target" ] || fail 'package target mismatch'
archive_root=agent-session-grep-v$version-$target
[ "${manifest##*/}" = "$archive_root.manifest.json" ] || fail 'manifest name mismatch'
[ "$(json_string "$manifest" root)" = "$archive_root" ] || fail 'manifest root mismatch'
[ "$(json_string "$manifest" version)" = "$version" ] || fail 'manifest version mismatch'
[ "$(json_string "$manifest" target)" = "$target" ] || fail 'manifest target mismatch'
[ "$(json_string "$manifest" source_commit)" = "$commit" ] || fail 'manifest commit mismatch'
archive=$(json_string "$manifest" filename)
case $archive in "$archive_root.zip"|"$archive_root.tar.gz") ;; *) fail 'archive name mismatch' ;; esac
# The canonical archive digest has four-space indentation, distinct from its
# file list's nested digests. Reject zero/multiple matches.
archive_hash=$(awk '/^    "sha256": "[0-9a-f]+",$/ {gsub(/[",]/, "", $2); print $2; n++} END {if(n!=1) exit 1}' "$manifest") || fail 'invalid archive digest'
[ "$(checksum_for "$archive")" = "$archive_hash" ] || fail 'archive checksum mismatch'
# SHA256SUMS is shared by all four target archives and their manifests.
awk -v version="$version" '
    BEGIN {
        allowed["THIRD-PARTY-DEPENDENCIES.json"]=1; allowed["THIRD-PARTY-DEPENDENCIES.csv"]=1
        split("x86_64-pc-windows-msvc x86_64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin", targets, " ")
        for(i=1;i<=4;i++) {
            root="agent-session-grep-v" version "-" targets[i]
            allowed[root ".manifest.json"]=1
            allowed[root ".zip"]=1; allowed[root ".tar.gz"]=1
        }
    }
    !($2 in allowed) {exit 1}
' "$checksums" || fail 'unexpected release checksum asset'


validate_tree() {
    tree=$1
    plain_path "$tree"
    bad=$(find "$tree" ! -type f ! -type d -print)
    [ -z "$bad" ] || fail 'non-regular package member'
    # Directories must be exactly the version ancestors, plus the versioned
    # helper directory when this package carries the immutable helper pair.
    count=$(find "$tree" -type d -print | wc -l | tr -d ' ')
    [ "$count" = "$expected_dirs" ] || fail 'unexpected package directory'
    count=$(find "$tree" -type f -print | wc -l | tr -d ' ')
    [ "$count" = "$expected_count" ] || fail 'unexpected package file count'
    while IFS="$tab" read -r kind hash mode size name; do
        [ "$kind" = file ] || continue
        safe_relative "$name"
        case $name in
            agent-session-grep|asg|current.json|"$dir/agent-session-grep"|"$dir/asg-supervisor"|"$dir/release.json"|"$helper_sh"|"$helper_ps1"|"$uninstall_tail"|package-install.ps1|package-install.sh|INSTALL-AND-UPGRADE.md|README.md|CHANGELOG.md|LICENSE-MIT|LICENSE-APACHE|NOTICE|SECURITY.md|THIRD-PARTY-DEPENDENCIES.json|THIRD-PARTY-DEPENDENCIES.csv) ;;
            *) fail 'unexpected package member' ;;
        esac
        case $name in agent-session-grep|asg|"$dir/$app"|"$dir/$supervisor"|"$helper_sh"|package-install.sh) expected_mode=0755 ;; *) expected_mode=0644 ;; esac
        [ "$mode" = "$expected_mode" ] || fail 'unexpected member mode'
        [ "$(digest "$tree/$name")" = "$hash" ] || fail 'package file checksum mismatch'
        [ "$(wc -c < "$tree/$name" | tr -d ' ')" = "$size" ] || fail 'package file size mismatch'
    done < "$files"
    [ "$(digest "$tree/PACKAGE-MANIFEST.tsv")" = "$files_hash" ] || fail 'installed file manifest changed'
    if [ "$tree" != "$root" ]; then
        regular "$tree/release.manifest.json"; regular "$tree/SHA256SUMS"
        [ "$(digest "$tree/release.manifest.json")" = "$manifest_hash" ] || fail 'installed release manifest changed'
        cmp -s "$checksums" "$tree/SHA256SUMS" || fail 'installed release checksums changed'
    fi
}
helper_sh="$dir/helpers/update-check.sh"
helper_ps1="$dir/helpers/update-check.ps1"
uninstall_tail="$dir/helpers/package-uninstall.ps1"
has_member() {
    awk -F '\t' -v name="$1" '$1=="file" && $5==name {n++} END {exit !(n==1)}' "$files"
}
record_count=$(awk -F '\t' '$1=="file" {n++} END {print n+0}' "$files")
if has_member "$helper_sh" || has_member "$helper_ps1"; then
    # The immutable pair is all-or-nothing; a single helper is a forged or
    # truncated inventory, never an older package.
    helper_count=19
    if has_member "$uninstall_tail"; then helper_count=20; fi
    if ! has_member "$helper_sh" || ! has_member "$helper_ps1" || [ "$record_count" != "$helper_count" ]; then
        fail 'incomplete or unexpected helper inventory'
    fi
    helpers=1
    expected_dirs=4
else
    [ "$record_count" = 17 ] || fail 'missing package members'
    helpers=0
    expected_dirs=3
fi
expected_count=$((record_count + 1))
validate_tree "$root"
[ "$(digest "$root/agent-session-grep")" = "$(digest "$root/asg")" ] || fail 'launcher copies differ'
[ "$(digest "$root/$dir/$app")" = "$app_hash" ] || fail 'application digest mismatch'
[ "$(digest "$root/$dir/$supervisor")" = "$supervisor_hash" ] || fail 'supervisor digest mismatch'
[ "$supervisor_hash" != "$app_hash" ] && [ "$supervisor_hash" != "$(digest "$root/asg")" ] || fail 'supervisor must be a distinct executable'
native_image() {
    # Byte reads are host-endian independent; no candidate is executed before
    # its entire manifest, digest and native architecture have been verified.
    regular "$1"
    od -An -v -tu1 -N64 "$1" | awk -v target="$target" '
        {for(i=1;i<=NF;i++) a[++n]=$i}
        END {
            elf=(n>=64 && a[1]==127 && a[2]==69 && a[3]==76 && a[4]==70 && a[5]==2 && a[6]==1 && (a[17]==2 || a[17]==3) && a[18]==0 && a[19]==62 && a[20]==0)
            macho=(n>=32 && a[1]==207 && a[2]==250 && a[3]==237 && a[4]==254 && a[6]==0 && a[7]==0 && a[8]==1 && a[17]==2 && a[18]==0 && a[19]==0 && a[20]==0)
            if(target=="x86_64-unknown-linux-gnu" && elf) exit 0
            if(target=="x86_64-apple-darwin" && macho && a[5]==7) exit 0
            if(target=="aarch64-apple-darwin" && macho && a[5]==12) exit 0
            exit 1
        }
    ' || fail 'executable native target mismatch'
}
for name in agent-session-grep asg "$dir/$app" "$dir/$supervisor"; do native_image "$root/$name"; done
[ "$(json_string "$root/current.json" schema)" = asg.current/v1 ] || fail 'current schema mismatch'
[ "$(json_string "$root/current.json" version)" = "$version" ] || fail 'current version mismatch'
[ "$(json_string "$root/current.json" dir)" = "$dir" ] || fail 'current directory mismatch'
[ "$(json_string "$root/current.json" app)" = "$app" ] || fail 'current app mismatch'
[ "$(json_string "$root/current.json" app_sha256)" = "$app_hash" ] || fail 'current digest mismatch'
[ "$(json_string "$root/$dir/release.json" schema)" = asg.version/v1 ] || fail 'release schema mismatch'
[ "$(json_string "$root/$dir/release.json" version)" = "$version" ] || fail 'release version mismatch'
[ "$(json_string "$root/$dir/release.json" target)" = "$target" ] || fail 'release target mismatch'
[ "$(json_string "$root/$dir/release.json" source_commit)" = "$commit" ] || fail 'release commit mismatch'
[ "$(json_string "$root/$dir/release.json" app_sha256)" = "$app_hash" ] || fail 'release digest mismatch'

# POSIX has no portable flock command. This first-install-only path publishes
# into a newly reserved directory, never replaces an existing installation.
# A crash leaves an explicit incomplete directory; no age/PID-based stealing.
if [ -z "$prefix" ]; then
    [ -n "${HOME:-}" ] || fail 'pass --prefix with a dedicated directory'
    prefix=${XDG_DATA_HOME:-$HOME/.local/share}/agent-session-grep-candidate/bin
fi
prefix=$(absolute "$prefix"); prefix=${prefix%/}
plain_path "$prefix"
case $prefix in "$root"|"$root"/*|/) fail 'prefix must be a separate dedicated directory' ;; esac
parent=${prefix%/*}; [ -n "$parent" ] || parent=/
plain_path "$parent"
mkdir -p "$parent"
plain_path "$parent"
cleanup() {
    if [ -n "$probe_pid" ]; then kill -KILL "$probe_pid" 2>/dev/null || :; fi
    if [ -n "$watchdog" ]; then kill "$watchdog" 2>/dev/null || :; fi
    [ -z "$stage" ] || printf 'package-install: staging preserved at %s\n' "$stage" >&2
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
stage=$(mktemp -d "$parent/.asg-stage.XXXXXXXX")
plain_path "$stage"
receipt=$stage/package-install.json.expected
cat > "$receipt" <<EOF
{
  "schema": "asg.package-install/v1",
  "product": "agent-session-grep",
  "version": "$version",
  "target": "$target",
  "source_commit": "$commit",
  "launcher_protocol": 1,
  "manifest_sha256": "$manifest_hash",
  "archive_sha256": "$archive_hash",
  "package_files_sha256": "$files_hash"
}
EOF
probe() {
    executable=$1; argument=$2
    # Cap each output file at 32 file-size blocks and enforce a wall budget. Only --version
    # and the launcher's identity query are ever executed.
    (ulimit -f 32; exec "$executable" "$argument") > "$stage/probe.out" 2> "$stage/probe.err" &
    probe_pid=$!
    (
        sleeper=
        trap '[ -z "$sleeper" ] || kill "$sleeper" 2>/dev/null || :; exit 0' TERM HUP INT
        sleep 30 & sleeper=$!
        wait "$sleeper"
        kill -KILL "$probe_pid" 2>/dev/null || :
    ) >/dev/null 2>&1 &
    watchdog=$!
    probe_status=0; wait "$probe_pid" || probe_status=$?
    probe_pid=
    kill "$watchdog" 2>/dev/null || :
    wait "$watchdog" 2>/dev/null || :
    watchdog=
    [ "$probe_status" -eq 0 ] && [ ! -s "$stage/probe.err" ] || fail 'program probe failed'
    [ "$(wc -c < "$stage/probe.out" | tr -d ' ')" -le 8192 ] || fail 'probe output limit'
}
verify_programs() {
    install_root=$1
    for name in agent-session-grep asg "$dir/$app"; do
        probe "$install_root/$name" --version
        printf 'agent-session-grep %s\n' "$version" > "$stage/expected-version"
        cmp -s "$stage/probe.out" "$stage/expected-version" || fail 'unexpected version output'
    done
    probe "$install_root/$dir/$supervisor" --version
    printf 'asg-supervisor %s\n' "$version" > "$stage/expected-version"
    cmp -s "$stage/probe.out" "$stage/expected-version" || fail 'unexpected supervisor version output'
    for name in agent-session-grep asg; do
        probe "$install_root/$name" --asg-launcher-info
        # Launcher emits this fixed, bounded JSON shape; no generic JSON parser
        # or eval is needed. Whitespace is the only permitted representation gap.
        tr -d ' \r\n\t' < "$stage/probe.out" > "$stage/actual-info"
        printf '{"schema":"asg.launcher-info/v1","launcher_protocol":1,"target":"%s","generation":1,"version":"%s","source_commit":"%s","app_sha256":"%s","catalog_schema":%s,"control_schema":%s}' "$target" "$version" "$commit" "$app_hash" "$(field catalog_schema)" "$(field control_schema)" > "$stage/expected-info"
        cmp -s "$stage/actual-info" "$stage/expected-info" || fail 'launcher identity mismatch'
    done
}
if [ -e "$prefix" ]; then
    [ -d "$prefix" ] || fail 'prefix is not a directory'
    existing=$(find "$prefix" ! -path "$prefix" -print)
    if [ -n "$existing" ]; then
        regular "$prefix/package-install.json"
        cmp -s "$receipt" "$prefix/package-install.json" || fail 'unowned prefix or different package; upgrade is not implemented'
        expected_count=$((record_count + 4)); validate_tree "$prefix"
        verify_programs "$prefix"
        # Remove only our exact temporary probe files and then the empty stage.
        rm "$receipt" "$stage/probe.out" "$stage/probe.err" "$stage/expected-version" "$stage/actual-info" "$stage/expected-info"
        rmdir "$stage"; stage=
        printf 'package-install: same verified developer candidate already installed at %s\n' "$prefix"
        complete_selected_setup
        exit 0
    fi
    fail 'first install requires an absent dedicated prefix; refusing an existing empty directory'
fi
payload=$stage/payload
mkdir "$payload"
while IFS="$tab" read -r kind hash mode size name; do
    [ "$kind" = file ] || continue
    case $name in */*) mkdir -p "$payload/${name%/*}" ;; esac
    cp "$root/$name" "$payload/$name"
    chmod "$mode" "$payload/$name"
done < "$files"
cp "$files" "$payload/PACKAGE-MANIFEST.tsv"
cp "$manifest" "$payload/release.manifest.json"
cp "$checksums" "$payload/SHA256SUMS"
chmod 644 "$payload/release.manifest.json" "$payload/SHA256SUMS"
expected_count=$((record_count + 3)); validate_tree "$payload"
verify_programs "$payload"
cp "$receipt" "$payload/package-install.json"
chmod 600 "$payload/package-install.json"
sync
# mkdir is an exclusive reservation of a new install, not a staleable lease.
mkdir "$prefix" || fail 'prefix was concurrently occupied'
mkdir "$prefix/versions"
for name in agent-session-grep asg "$dir" package-install.ps1 package-install.sh INSTALL-AND-UPGRADE.md README.md CHANGELOG.md LICENSE-MIT LICENSE-APACHE NOTICE SECURITY.md THIRD-PARTY-DEPENDENCIES.json THIRD-PARTY-DEPENDENCIES.csv PACKAGE-MANIFEST.tsv release.manifest.json SHA256SUMS; do
    mv "$payload/$name" "$prefix/$name"
done
# The pointer and receipt are the last files, each published by same-volume rename.
mv "$payload/current.json" "$prefix/current.json"
mv "$payload/package-install.json" "$prefix/package-install.json"
sync
rmdir "$payload/versions" "$payload"
rm "$receipt" "$stage/probe.out" "$stage/probe.err" "$stage/expected-version" "$stage/actual-info" "$stage/expected-info"
rmdir "$stage"; stage=
printf 'package-install: verified developer candidate %s installed at %s\n' "$version" "$prefix"
complete_selected_setup
