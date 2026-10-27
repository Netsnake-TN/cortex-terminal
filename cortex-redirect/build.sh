#!/usr/bin/env bash
set -euo pipefail

# cortex-redirect/build.sh — builds the cortex-redirect seccomp supervisor
# from source and copies it into app/src/main/assets/ so Gradle embeds it
# in the APK. No prebuilt binary is shipped.
#
# Triggered by .github/workflows/build-release.yml.
#
# Output: app/src/main/assets/cortex-redirect (aarch64 glibc ELF)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSET_DEST="$PROJECT_ROOT/app/src/main/assets/cortex-redirect"

SRC="$SCRIPT_DIR/cortex-redirect.c"

echo "[cortex-redirect] Building glibc ELF supervisor (aarch64-linux-gnu)..."

# Build with the Debian/Ubuntu aarch64 glibc cross-compiler. A glibc (not bionic)
# binary is required so the guest's LD_PRELOAD hook can load into this entry
# point at runtime inside the Android guest.
aarch64-linux-gnu-gcc -std=gnu11 -O2 -Wall -Wextra \
    -o "$ASSET_DEST" \
    "$SRC"

chmod 755 "$ASSET_DEST"

# Sanity check: must be an aarch64 ELF
if ! file "$ASSET_DEST" | grep -q "aarch64"; then
    echo "[cortex-redirect] ERROR: output is not an aarch64 ELF"
    exit 1
fi

echo "[cortex-redirect] Built: $ASSET_DEST"
file "$ASSET_DEST"
echo "[cortex-redirect] Done. Gradle will embed it in the APK."