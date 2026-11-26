#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="/tmp/nodejs/bin:$HOME/.cargo/bin:$PATH"
export npm_config_cache="/tmp/.npm"

echo "=================================================="
echo "Starting npm smoke test..."
echo "=================================================="

TMP_DIR=$(mktemp -d /tmp/gitprotect-smoke-XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Created temp test directory: $TMP_DIR"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Darwin)
        if [ "$ARCH" = "arm64" ]; then
            PLATFORM_PKG="gitprotect-darwin-arm64"
        else
            PLATFORM_PKG="gitprotect-darwin-x64"
        fi
        ;;
    Linux)
        if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
            PLATFORM_PKG="gitprotect-linux-arm64"
        else
            PLATFORM_PKG="gitprotect-linux-x64"
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        PLATFORM_PKG="gitprotect-win32-x64"
        ;;
    *)
        echo "Warning: Unknown OS $OS, defaulting to x64"
        PLATFORM_PKG="gitprotect-linux-x64"
        ;;
esac

echo "Detected current host platform: $OS ($ARCH) -> $PLATFORM_PKG"

echo "Packing platform packages into temp directory..."
if [ -d "npm/$PLATFORM_PKG" ]; then
    (cd "npm/$PLATFORM_PKG" && npm pack --pack-destination "$TMP_DIR" >/dev/null)
fi

if [ "$OS" = "Darwin" ]; then
    if [ "$PLATFORM_PKG" = "gitprotect-darwin-arm64" ] && [ -f "npm/gitprotect-darwin-x64/bin/gitprotect" ]; then
        (cd "npm/gitprotect-darwin-x64" && npm pack --pack-destination "$TMP_DIR" >/dev/null)
    elif [ "$PLATFORM_PKG" = "gitprotect-darwin-x64" ] && [ -f "npm/gitprotect-darwin-arm64/bin/gitprotect" ]; then
        (cd "npm/gitprotect-darwin-arm64" && npm pack --pack-destination "$TMP_DIR" >/dev/null)
    fi
fi

(cd npm/gitprotect && npm pack --pack-destination "$TMP_DIR" >/dev/null)

echo "Packed tarballs:"
ls -la "$TMP_DIR"

cd "$TMP_DIR"
npm init -y >/dev/null 2>&1

MAIN_TGZ=$(ls akshathk-gitprotect-0*.tgz | grep -v darwin | grep -v linux | grep -v win32 | head -n1)
PLATFORM_TGZ=$(ls *"$PLATFORM_PKG"*.tgz | head -n1)

echo "Attempting to install only the main package tarball first ($MAIN_TGZ)..."
if npm install "$MAIN_TGZ" --no-audit --no-fund --offline 2>&1; then
    echo "Main tarball installed. Testing binary execution..."
    if ./node_modules/.bin/gitprotect --version 2>/dev/null; then
        echo "Main tarball alone resolved platform package successfully."
    else
        echo "REPORT: Installing main package alone cannot resolve the platform package without a registry because optionalDependencies are fetched by version from the registry."
    fi
else
    echo "REPORT: Installing main package alone failed without a registry because optionalDependencies are fetched from the registry."
fi

echo "Installing local platform tarball ($PLATFORM_TGZ) alongside main tarball ($MAIN_TGZ)..."
npm install "$PLATFORM_TGZ" "$MAIN_TGZ" --no-audit --no-fund --offline >/dev/null

echo "Verifying installed gitprotect binary..."
INSTALLED_VERSION=$(./node_modules/.bin/gitprotect --version)
echo "Output from ./node_modules/.bin/gitprotect --version:"
echo "$INSTALLED_VERSION"

if ! echo "$INSTALLED_VERSION" | grep -q "gitprotect"; then
    echo "Smoke test FAILED: Unexpected output from --version: $INSTALLED_VERSION" >&2
    exit 1
fi

echo "=================================================="
echo "Running real Git hook commit-block test..."
echo "=================================================="
TEST_REPO="$TMP_DIR/test-repo"
mkdir -p "$TEST_REPO"
cd "$TEST_REPO"

git init >/dev/null 2>&1
git config user.name "Test User"
git config user.email "test@example.com"
git config commit.gpgsign false

echo "Running gitprotect init..."
"$TMP_DIR/node_modules/.bin/gitprotect" init

# 1. Clean commit should succeed
echo "fn main() {}" > clean.rs
git add clean.rs
git commit -m "clean commit" >/dev/null 2>&1
echo "Clean commit succeeded."

# 2. Commit with fake runtime-built secret should be blocked and redacted
FAKE_KEY=$(node -e 'console.log("AKIA" + "A".repeat(16))')
echo "AWS_KEY=$FAKE_KEY" > secret.txt
git add secret.txt

if git commit -m "commit secret" > commit.log 2>&1; then
    echo "ERROR: Commit with secret unexpectedly succeeded!" >&2
    exit 1
else
    COMMIT_OUTPUT=$(cat commit.log)
    echo "Commit was blocked as expected."
fi

# Verify secret is masked and never printed raw
if echo "$COMMIT_OUTPUT" | grep -q "\[REDACTED_SEC-001\]"; then
    echo "Redaction tag [REDACTED_SEC-001] confirmed in output."
else
    echo "ERROR: [REDACTED_SEC-001] missing from commit output:" >&2
    echo "$COMMIT_OUTPUT" >&2
    exit 1
fi

if echo "$COMMIT_OUTPUT" | grep -q "$FAKE_KEY"; then
    echo "SECURITY INVARIANT VIOLATION: Raw fake key found in output!" >&2
    exit 1
fi

echo "Smoke test PASSED: gitprotect CLI executed successfully and hook blocked/redacted secret cleanly."
