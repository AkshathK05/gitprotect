#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="/tmp/nodejs/bin:$HOME/.cargo/bin:$PATH"
export npm_config_cache="/tmp/.npm"

echo "Building gitprotect macOS targets..."
TARGETS=(
  "aarch64-apple-darwin:npm/gitprotect-darwin-arm64:gitprotect"
  "x86_64-apple-darwin:npm/gitprotect-darwin-x64:gitprotect"
)

for entry in "${TARGETS[@]}"; do
  TARGET="${entry%%:*}"
  REST="${entry#*:}"
  PKG_DIR="${REST%%:*}"
  BIN_NAME="${REST#*:}"

  echo "--------------------------------------------------"
  echo "Target: $TARGET -> $PKG_DIR"
  echo "--------------------------------------------------"
  cargo build --release --target "$TARGET" --bin gitprotect

  BIN_SRC="target/$TARGET/release/$BIN_NAME"
  BIN_DEST="$PKG_DIR/bin/$BIN_NAME"

  mkdir -p "$PKG_DIR/bin"
  cp "$BIN_SRC" "$BIN_DEST"
  chmod +x "$BIN_DEST"

  codesign --force -s - "$BIN_DEST"
  echo "Ad-hoc code signing applied to $BIN_DEST"
  codesign -v "$BIN_DEST"
done

# If cross-compilers are available, build Linux and Windows binaries
if command -v cargo-zigbuild >/dev/null 2>&1; then
  echo "Building Linux targets with cargo-zigbuild..."
  cargo zigbuild --release --target x86_64-unknown-linux-musl --bin gitprotect
  mkdir -p npm/gitprotect-linux-x64/bin
  cp target/x86_64-unknown-linux-musl/release/gitprotect npm/gitprotect-linux-x64/bin/gitprotect
  chmod +x npm/gitprotect-linux-x64/bin/gitprotect

  cargo zigbuild --release --target aarch64-unknown-linux-musl --bin gitprotect
  mkdir -p npm/gitprotect-linux-arm64/bin
  cp target/aarch64-unknown-linux-musl/release/gitprotect npm/gitprotect-linux-arm64/bin/gitprotect
  chmod +x npm/gitprotect-linux-arm64/bin/gitprotect
fi

if command -v cargo-xwin >/dev/null 2>&1; then
  echo "Building Windows target with cargo-xwin..."
  cargo xwin build --release --target x86_64-pc-windows-msvc --bin gitprotect
  mkdir -p npm/gitprotect-win32-x64/bin
  cp target/x86_64-pc-windows-msvc/release/gitprotect.exe npm/gitprotect-win32-x64/bin/gitprotect.exe
fi

echo "=================================================="
echo "Verifying binaries and architectures..."
echo "=================================================="

CHECKS=(
  "npm/gitprotect-darwin-arm64/bin/gitprotect:Mach-O.*arm64"
  "npm/gitprotect-darwin-x64/bin/gitprotect:Mach-O.*x86_64"
  "npm/gitprotect-linux-x64/bin/gitprotect:ELF.*x86-64"
  "npm/gitprotect-linux-arm64/bin/gitprotect:ELF.*aarch64"
  "npm/gitprotect-win32-x64/bin/gitprotect.exe:PE32\+.*x86-64"
)

for check in "${CHECKS[@]}"; do
  BIN_PATH="${check%%:*}"
  EXPECTED_ARCH="${check#*:}"

  if [ ! -f "$BIN_PATH" ]; then
    echo "ERROR: Missing required binary: $BIN_PATH" >&2
    exit 1
  fi

  FILE_INFO=$(file "$BIN_PATH")
  echo "$FILE_INFO"

  if ! echo "$FILE_INFO" | grep -qE "$EXPECTED_ARCH"; then
    echo "ERROR: Binary $BIN_PATH does not match expected architecture pattern '$EXPECTED_ARCH'" >&2
    echo "Actual file info: $FILE_INFO" >&2
    exit 1
  fi
done

echo "=================================================="
echo "Syncing root README.md and LICENSE into npm packages..."
echo "=================================================="
cp "$REPO_ROOT/README.md" "$REPO_ROOT/npm/gitprotect/README.md"
for pkg_dir in "$REPO_ROOT"/npm/*; do
  if [ -d "$pkg_dir" ]; then
    cp "$REPO_ROOT/LICENSE" "$pkg_dir/LICENSE"
  fi
done

echo "=================================================="
echo "Running npm pack --dry-run in each package..."
echo "=================================================="

PACKAGES=(
  "npm/gitprotect"
  "npm/gitprotect-darwin-arm64"
  "npm/gitprotect-darwin-x64"
  "npm/gitprotect-linux-x64"
  "npm/gitprotect-linux-arm64"
  "npm/gitprotect-win32-x64"
)

for pkg in "${PACKAGES[@]}"; do
  echo "--------------------------------------------------"
  echo "Package: $pkg"
  echo "--------------------------------------------------"
  PACK_OUTPUT=$(cd "$pkg" && npm pack --dry-run 2>&1)
  echo "$PACK_OUTPUT"

  TOTAL_FILES=$(echo "$PACK_OUTPUT" | grep "total files:" | awk '{print $NF}')
  if [ -n "$TOTAL_FILES" ] && [ "$TOTAL_FILES" -lt 2 ]; then
    echo "ERROR: Package $pkg packed with only $TOTAL_FILES file(s). Platform packages must contain binary and metadata." >&2
    exit 1
  fi
done

echo "Build, architecture verification, and pack dry-run completed successfully."
