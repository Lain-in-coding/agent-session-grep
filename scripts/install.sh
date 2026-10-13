#!/usr/bin/env bash
# Compatibility entrypoint kept for older documentation, bookmarks, and scripts
# that still reference scripts/install.sh. The installer implementation lives in
# scripts/install/install.sh; this wrapper only forwards arguments so the two
# entrypoints cannot drift and only one of them can clone or build anything.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
canonical="$script_dir/install/install.sh"

if [ ! -f "$canonical" ]; then
    printf 'install: error: %s not found; run this script from a checkout of the repository\n' \
        "$canonical" >&2
    exit 1
fi

exec bash "$canonical" "$@"
