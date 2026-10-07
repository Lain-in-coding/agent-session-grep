#!/usr/bin/env bash
# Build agent-session-grep from source and install the canonical command plus an
# asg alias into a user-level bin directory. The alias is a relative symlink
# when supported, with a marked wrapper fallback. The artifact is unsigned and
# unnotarized; this script deliberately does NOT edit PATH or shell profiles.

set -euo pipefail

fail() {
    printf 'install: error: %s\n' "$1" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: install.sh [--prefix <dir>] [--skip-build] [--dry-run]

  --prefix <dir>  install directory (default: ${XDG_BIN_HOME:-$HOME/.local/bin})
  --skip-build    copy an already-built target/release artifact instead of building
  --dry-run       print the planned actions without writing anything
EOF
}

prefix=""
skip_build=0
dry_run=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            [ $# -ge 2 ] || fail '--prefix requires a directory'
            prefix="$2"
            shift 2
            ;;
        --skip-build)
            skip_build=1
            shift
            ;;
        --dry-run)
            dry_run=1
            shift
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
[ -f "$repo_root/Cargo.toml" ] || \
    fail "cannot find Cargo.toml at $repo_root; run this script from a checkout of the repository"

binary_name="agent-session-grep"
alias_name="asg"
wrapper_marker="# agent-session-grep managed asg wrapper"

if [ -z "$prefix" ]; then
    if [ -n "${XDG_BIN_HOME:-}" ]; then
        prefix="$XDG_BIN_HOME"
    elif [ -n "${HOME:-}" ]; then
        prefix="$HOME/.local/bin"
    else
        fail 'neither XDG_BIN_HOME nor HOME is set; pass --prefix <dir> to choose an install directory'
    fi
fi

artifact="$repo_root/target/release/$binary_name"

if [ "$skip_build" -eq 0 ]; then
    # cargo is only required on the build path; --skip-build exists precisely
    # for hosts that already have the artifact.
    command -v cargo >/dev/null 2>&1 || \
        fail 'cargo not found on PATH; install a Rust toolchain from https://rustup.rs and re-run'
    cargo --version || fail 'cargo --version failed'

    if [ "$dry_run" -eq 1 ]; then
        printf 'install: dry run: would run cargo build --locked --release -p agent-session-grep-cli in %s\n' "$repo_root"
    else
        # --locked keeps the build reproducible: an install must never silently
        # resolve different dependency versions than CI did.
        (cd "$repo_root" && cargo build --locked --release -p agent-session-grep-cli) || \
            fail 'cargo build failed'
    fi
fi

if [ "$dry_run" -eq 1 ] && [ ! -f "$artifact" ]; then
    printf 'install: dry run: no file written\n'
    printf 'install: dry run: would install %s -> %s\n' "$artifact" "$prefix/$binary_name"
    printf 'install: dry run: would link %s -> %s\n' "$prefix/$alias_name" "$binary_name"
    exit 0
fi

if [ ! -f "$artifact" ]; then
    if [ "$skip_build" -eq 1 ]; then
        fail "$artifact does not exist; --skip-build requires a prior cargo build --locked --release -p agent-session-grep-cli"
    fi
    fail "$artifact does not exist after a successful build"
fi

# No third-party tools: whichever of the two standard checksum utilities the
# platform ships (coreutils on Linux, BSD shasum on macOS) is used, and a
# missing digest is reported rather than silently skipped.
sha256=""
if command -v sha256sum >/dev/null 2>&1; then
    sha256=$(sha256sum "$artifact" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    sha256=$(shasum -a 256 "$artifact" | cut -d' ' -f1)
else
    sha256="unavailable (no sha256sum or shasum on PATH)"
fi

target="$prefix/$binary_name"
alias_target="$prefix/$alias_name"

alias_is_managed() {
    if [ -L "$alias_target" ]; then
        alias_link=$(readlink "$alias_target") || return 1
        [ "$alias_link" = "$binary_name" ] || [ "$alias_link" = "$target" ]
    elif [ -f "$alias_target" ]; then
        [ "$(sed -n '2p' "$alias_target")" = "$wrapper_marker" ] || \
            { [ -f "$target" ] && cmp -s "$alias_target" "$target"; }
    else
        return 1
    fi
}

# A custom prefix may be shared. Replace only an alias that this installer can
# identify (our symlink, marked wrapper, or an older identical executable copy).
if { [ -e "$alias_target" ] || [ -L "$alias_target" ]; } && ! alias_is_managed; then
    fail "$alias_target already exists and is not a managed agent-session-grep alias"
fi

if [ "$dry_run" -eq 1 ]; then
    printf 'install: dry run: no file written\n'
    printf 'install: dry run: would create directory %s\n' "$prefix"
    printf 'install: dry run: would copy %s -> %s\n' "$artifact" "$target"
    printf 'install: dry run: would link %s -> %s (with a marked wrapper fallback)\n' "$alias_target" "$binary_name"
    printf 'install: dry run: artifact sha256 %s\n' "$sha256"
    exit 0
fi

mkdir -p "$prefix" || fail "cannot create install directory $prefix"
# Stage both files before replacement. The relative link remains valid if the
# prefix directory is moved as a unit.
tmp_target="$prefix/.$binary_name.tmp.$$"
tmp_alias="$prefix/.$alias_name.tmp.$$"
cp -f "$artifact" "$tmp_target" || fail "cannot stage the binary in $prefix"
chmod +x "$tmp_target" || { rm -f "$tmp_target"; fail "cannot mark the staged binary executable"; }
if ! ln -s "$binary_name" "$tmp_alias" 2>/dev/null; then
    cat > "$tmp_alias" <<'EOF'
#!/usr/bin/env sh
# agent-session-grep managed asg wrapper
exec "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/agent-session-grep" "$@"
EOF
    chmod +x "$tmp_alias" || { rm -f "$tmp_target" "$tmp_alias"; fail "cannot create the asg wrapper in $prefix"; }
fi
mv -f "$tmp_target" "$target" || { rm -f "$tmp_target" "$tmp_alias"; fail "cannot atomically replace $target"; }
mv -f "$tmp_alias" "$alias_target" || { rm -f "$tmp_alias"; fail "cannot atomically replace $alias_target"; }

version_line=$("$target" --version) || \
    fail "installed binary failed its self check: $target --version did not exit 0"
alias_version_line=$("$alias_target" --version) || \
    fail "installed alias failed its self check: $alias_target --version did not exit 0"
[ "$version_line" = "$alias_version_line" ] || \
    fail 'installed commands reported different versions'

printf 'install: installed %s\n' "$version_line"
printf 'install: command  %s\n' "$target"
printf 'install: alias    %s\n' "$alias_target"
printf 'install: sha256   %s\n' "$sha256"
printf 'install: this script does not modify PATH. To use the binary by name in\n'
printf 'install: the current shell session, run:\n'
printf 'install:   export PATH="%s:$PATH"\n' "$prefix"
printf 'install: to make it permanent, add %s to PATH yourself.\n' "$prefix"
printf 'install: the artifact is unsigned and unnotarized.\n'
exit 0
