#!/usr/bin/env bash
# Prepare every repository and host executable needed by Liter8.
#
# Swift compilation remains in `make build`. This script handles the things
# SwiftPM does not own: recursive Git submodules and external host tools. All
# downloads/builds are cached locally, and only finished binaries are published
# into tools/, so an interrupted setup never replaces a working executable.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPOSITORY_DIR="$(git -C "$PROJECT_DIR" rev-parse --show-toplevel)"
CACHE_DIR="$PROJECT_DIR/.setup-cache"
TOOLS_DIR="$PROJECT_DIR/tools"

LOG_FILE="$CACHE_DIR/setup.log"
IDEVICERESTORE_SUBMODULE="$PROJECT_DIR/vendor/idevicerestore"

say() { printf '[*] %s\n' "$1"; }
die() { printf '[!] %s\n' "$1" >&2; exit 1; }

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing setup dependency: $1"
}

fail_with_log() {
    printf '[!] setup phase failed; last 80 log lines follow\n' >&2
    tail -n 80 "$LOG_FILE" >&2 || true
    printf '[!] complete log: %s\n' "$LOG_FILE" >&2
    exit 1
}

atomic_install() {
    local source="$1" destination="$2"
    local temporary="$destination.setup-new"
    cp "$source" "$temporary"
    chmod 755 "$temporary"
    mv -f "$temporary" "$destination"
}

require_command git
require_command make
require_command autoconf
require_command automake
require_command pkg-config
require_command tar
require_command ipsw
require_command aea
mkdir -p "$CACHE_DIR" "$TOOLS_DIR"
: > "$LOG_FILE"

say "initializing repository submodules recursively"
git -C "$REPOSITORY_DIR" submodule update --init --recursive --quiet \
    >>"$LOG_FILE" 2>&1 || fail_with_log
[[ -d "$IDEVICERESTORE_SUBMODULE/.git" || -f "$IDEVICERESTORE_SUBMODULE/.git" ]] \
    || die "idevicerestore submodule was not initialized"

# The repository's gitlink is the version lock. setup never follows the moving
# master branch after clone, so every checkout builds its reviewed revision.
IDEVICERESTORE_COMMIT="$(git -C "$IDEVICERESTORE_SUBMODULE" rev-parse HEAD)"
IDEVICERESTORE_VERSION="$(git -C "$IDEVICERESTORE_SUBMODULE" describe --always --tags)"

IDEVICE_MARKER="$TOOLS_DIR/.idevicerestore-commit"
if [[ -x "$TOOLS_DIR/idevicerestore" ]] \
    && [[ "$(cat "$IDEVICE_MARKER" 2>/dev/null || true)" == "$IDEVICERESTORE_COMMIT" ]]; then
    say "idevicerestore is already built at $IDEVICERESTORE_COMMIT"
else
    IDEVICE_SOURCE="$CACHE_DIR/idevicerestore-source-$IDEVICERESTORE_COMMIT"
    IDEVICE_BUILD="$CACHE_DIR/idevicerestore-build-$IDEVICERESTORE_COMMIT"
    if [[ ! -f "$IDEVICE_SOURCE/.liter8-autogen-complete" ]]; then
        # A killed autogen must not poison later setup runs with Autom4te's
        # cached empty version. Preserve the failed tree for its log context
        # and prepare a fresh export atomically.
        if [[ -d "$IDEVICE_SOURCE" ]]; then
            mv "$IDEVICE_SOURCE" "$CACHE_DIR/.failed-idevicerestore-source-$$"
        fi
        say "exporting idevicerestore submodule at $IDEVICERESTORE_COMMIT"
        IDEVICE_SOURCE_STAGING="$(mktemp -d "$CACHE_DIR/.idevicerestore-source.XXXXXX")"
        git -C "$IDEVICERESTORE_SUBMODULE" archive HEAD \
            | tar -x -C "$IDEVICE_SOURCE_STAGING"

        # git-version-gen cannot see `.git` inside an exported source tree.
        # Write the upstream tarball version before autogen reads configure.ac.
        printf '%s\n' "$IDEVICERESTORE_VERSION" \
            > "$IDEVICE_SOURCE_STAGING/.tarball-version"
        say "generating idevicerestore build system"
        (cd "$IDEVICE_SOURCE_STAGING" && NOCONFIGURE=1 ./autogen.sh) \
            >>"$LOG_FILE" 2>&1 || fail_with_log
        touch "$IDEVICE_SOURCE_STAGING/.liter8-autogen-complete"
        mv "$IDEVICE_SOURCE_STAGING" "$IDEVICE_SOURCE"
    else
        say "using cached idevicerestore build system"
    fi
    mkdir -p "$IDEVICE_BUILD"

    # Homebrew links most .pc files into its main prefix, while libtatsu also
    # ships one under its formula prefix. Include both without modifying the
    # user's global pkg-config configuration.
    SETUP_PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-}"
    if command -v brew >/dev/null 2>&1; then
        BREW_PREFIX="$(brew --prefix)"
        SETUP_PKG_CONFIG_PATH="$BREW_PREFIX/lib/pkgconfig:$BREW_PREFIX/opt/libtatsu/lib/pkgconfig:$SETUP_PKG_CONFIG_PATH"
    fi
    PKG_CONFIG_PATH="$SETUP_PKG_CONFIG_PATH" pkg-config --exists \
        libirecovery-1.0 libimobiledevice-1.0 libusbmuxd-2.0 libplist-2.0 \
        libimobiledevice-glue-1.0 libtatsu-1.0 libzip libcurl zlib \
        || die "idevicerestore build libraries are missing; install its documented dependencies"

    say "configuring idevicerestore"
    (cd "$IDEVICE_BUILD" && PKG_CONFIG_PATH="$SETUP_PKG_CONFIG_PATH" "$IDEVICE_SOURCE/configure") \
        >>"$LOG_FILE" 2>&1 || fail_with_log
    JOBS="$(sysctl -n hw.logicalcpu 2>/dev/null || printf '4')"
    say "building idevicerestore with $JOBS jobs"
    make -C "$IDEVICE_BUILD" -j"$JOBS" >>"$LOG_FILE" 2>&1 || fail_with_log
    [[ -x "$IDEVICE_BUILD/src/idevicerestore" ]] \
        || die "idevicerestore build did not produce src/idevicerestore"
    atomic_install "$IDEVICE_BUILD/src/idevicerestore" "$TOOLS_DIR/idevicerestore"
    printf '%s\n' "$IDEVICERESTORE_COMMIT" > "$IDEVICE_MARKER.setup-new"
    mv -f "$IDEVICE_MARKER.setup-new" "$IDEVICE_MARKER"
fi

say "external tools ready in $TOOLS_DIR"
"$TOOLS_DIR/idevicerestore" --version
