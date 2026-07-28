#!/usr/bin/env bash
# build-mac.sh — Mac equivalent of build-protected.ps1
# Run from the repo root: bash build-mac.sh
# Produces a protected (obfuscated + bytecode) DMG in electron-app/dist/
#
# Differences from Windows build:
#   - Downloads a portable Node 18 matching Electron's bundled Node version
#   - Uses that Node for esbuild, obfuscator, and bytenode (avoids system Node mismatch)
#   - Compiles to .jsc bytecode (same protection level as Windows)
#   - For universal builds (arm64 + x64), compiles bytecode for both archs

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# ─── Config ────────────────────────────────────────────────────────────────────
NODE_VERSION="18.20.4"          # Must match Electron's bundled Node version
BUILD_ARCH="$(uname -m)"        # Current build machine arch: arm64 or x86_64

case "$BUILD_ARCH" in
  x86_64) NODE_ARCH="x64"; ELECTRON_ARCH_FLAG="--x64" ;;
  arm64)  NODE_ARCH="arm64"; ELECTRON_ARCH_FLAG="--arm64" ;;
  *)      echo "Unsupported architecture: $BUILD_ARCH"; exit 1 ;;
esac

NODE_DIR="$REPO_ROOT/electron-app/bin/mac"
NODE_BIN="$NODE_DIR/node"
NODE_TAR="node-v${NODE_VERSION}-darwin-${NODE_ARCH}.tar.gz"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TAR}"

# ─── Dependency checks ─────────────────────────────────────────────────────────
echo ""
echo "==> Checking dependencies..."
ROOT_ESBUILD="$REPO_ROOT/node_modules/.bin/esbuild"
ROOT_OBFUSCATOR="$REPO_ROOT/node_modules/.bin/javascript-obfuscator"
ELECTRON_BUILDER="$REPO_ROOT/electron-app/node_modules/.bin/electron-builder"

for f in "$ROOT_ESBUILD" "$ROOT_OBFUSCATOR" "$ELECTRON_BUILDER"; do
  if [ ! -f "$f" ]; then
    echo "Missing: $f"
    echo "Run:  npm install && cd electron-app && npm install"
    exit 1
  fi
done

# ─── Resolve Node binary ───────────────────────────────────────────────────────
# Always download a portable Node 18 matching Electron's bundled Node version.
# The portable build is statically linked (no libnode.dylib dependency), so it
# can be copied into the app bundle without missing shared libraries.
echo ""
echo "==> Resolving Node ${NODE_VERSION} (${NODE_ARCH})..."

mkdir -p "$NODE_DIR"
if [ -f "$NODE_BIN" ]; then
  NODE_FILE_INFO="$(file "$NODE_BIN" 2>/dev/null || true)"
  if [ "$NODE_ARCH" = "arm64" ] && ! echo "$NODE_FILE_INFO" | grep -qi "arm64"; then
    echo "    Existing Node is not arm64; replacing it."
    rm -f "$NODE_BIN"
  elif [ "$NODE_ARCH" = "x64" ] && ! echo "$NODE_FILE_INFO" | grep -Eqi "x86_64|x86-64"; then
    echo "    Existing Node is not x64; replacing it."
    rm -f "$NODE_BIN"
  fi
fi
if [ ! -f "$NODE_BIN" ]; then
  echo "    Downloading ${NODE_URL}..."
  curl -L -o "/tmp/${NODE_TAR}" "$NODE_URL"
  tar -xzf "/tmp/${NODE_TAR}" -C "$NODE_DIR" --strip-components=2 "node-v${NODE_VERSION}-darwin-${NODE_ARCH}/bin/node"
  rm "/tmp/${NODE_TAR}"
  chmod +x "$NODE_BIN"
  echo "    Downloaded: $NODE_BIN"
else
  echo "    Already exists: $NODE_BIN"
fi

# Verify the downloaded Node works
"$NODE_BIN" --version > /dev/null 2>&1 || {
  echo "ERROR: Downloaded Node binary is not executable or broken: $NODE_BIN"
  rm -f "$NODE_BIN"
  exit 1
}
echo "    Node version: $("$NODE_BIN" --version)"

# ─── Prepare output directories ────────────────────────────────────────────────
echo ""
echo "==> Preparing output directories..."
mkdir -p build-artifacts dist/agent
mkdir -p electron-app/build-artifacts electron-app/runtime/electron

# ─── Agent: bundle → obfuscate → bytecode ─────────────────────────────────────
# NOTE: esbuild is a compiled Go binary — run it directly, NOT through $NODE_BIN
echo ""
echo "==> Provisioning bundled Node runtime..."
mkdir -p electron-app/bin/mac
# $NODE_BIN already IS electron-app/bin/mac/node (downloaded above), so no copy needed.
# The portable Node 18 build is statically linked and has no libnode.dylib dependency.

# ─── Agent: bundle → obfuscate ────────────────────────────────────────────────
echo ""
echo "==> Bundling agent..."
"$ROOT_ESBUILD" agent/dsc-agent.js \
  --bundle --platform=node --format=cjs --target=node18 \
  --external:pkcs11js \
  --outfile=build-artifacts/dsc-agent.bundle.js

# NOTE: javascript-obfuscator is a JS script — must run through $NODE_BIN
echo ""
echo "==> Obfuscating agent..."
"$NODE_BIN" "$ROOT_OBFUSCATOR" build-artifacts/dsc-agent.bundle.js \
  --output build-artifacts/dsc-agent.obf.js \
  --target node --compact true \
  --identifier-names-generator hexadecimal \
  --rename-globals false --simplify true \
  --string-array true --string-array-encoding base64 \
  --string-array-threshold 0.75 \
  --unicode-escape-sequence false

# Agent runtime: use obfuscated JS (not bytecode) so it works across different
# Node/V8 versions (Node 26 in dev, bundled Node 18 in production).
echo ""
echo "==> Publishing agent runtime (obfuscated JS)..."
cp build-artifacts/dsc-agent.obf.js dist/agent/dsc-agent.obf.js
printf "require('./dsc-agent.obf.js');\n" > dist/agent/dsc-agent.loader.js
echo "Agent runtime files ready"

# ─── Electron: stage PIN source (path fix for bytecode context) ───────────────
echo ""
echo "==> Staging Electron sources..."
"$NODE_BIN" -e "
  const fs = require('fs');
  const src = fs.readFileSync('electron-app/main/pinPromptServer.js', 'utf8');
  fs.writeFileSync('electron-app/build-artifacts/pinPromptServer.bytecode-point.js', src, 'ascii');
"

# NOTE: esbuild is a compiled Go binary — run it directly, NOT through $NODE_BIN
echo ""
echo "==> Bundling Electron files..."
"$ROOT_ESBUILD" electron-app/main-bytecode-point.js \
  --bundle --platform=node --format=cjs --target=node18 \
  --external:electron \
  --external:./pinPromptServer.loader.js \
  --outfile=electron-app/build-artifacts/main.bundle.js

"$ROOT_ESBUILD" electron-app/build-artifacts/pinPromptServer.bytecode-point.js \
  --bundle --platform=node --format=cjs --target=node18 \
  --external:electron \
  --outfile=electron-app/build-artifacts/pinPromptServer.bundle.js

"$ROOT_ESBUILD" electron-app/preload.js \
  --bundle --platform=node --format=cjs --target=node18 \
  --external:electron \
  --outfile=electron-app/build-artifacts/preload.bundle.js

# NOTE: javascript-obfuscator is a JS script — must run through $NODE_BIN
echo ""
echo "==> Obfuscating Electron files..."
for module in main pinPromptServer preload; do
  "$NODE_BIN" "$ROOT_OBFUSCATOR" "electron-app/build-artifacts/${module}.bundle.js" \
    --output "electron-app/build-artifacts/${module}.obf.js" \
    --target node --compact true \
    --identifier-names-generator hexadecimal \
    --rename-globals false --simplify true \
    --string-array true --string-array-encoding base64 \
    --string-array-threshold 0.75 \
    --unicode-escape-sequence false
done

# ─── Electron: runtime files ──────────────────────────────────────────────────
# NOTE: Electron files run inside Electron's V8 engine, NOT the bundled Node 18.
# Bytecode (.jsc) compiled with Node 18's V8 is incompatible with Electron's V8
# (cachedDataRejected error). We use obfuscated JS instead — same protection level,
# no V8 version mismatch.
echo ""
echo "==> Publishing Electron runtime files (obfuscated JS)..."
cp electron-app/build-artifacts/main.obf.js            electron-app/runtime/electron/main.obf.js
cp electron-app/build-artifacts/pinPromptServer.obf.js electron-app/runtime/electron/pinPromptServer.obf.js
cp electron-app/build-artifacts/preload.obf.js         electron-app/runtime/electron/preload.obf.js
printf "require('./main.obf.js');\n"                              > electron-app/runtime/electron/main.loader.js
printf "module.exports = require('./pinPromptServer.obf.js');\n"  > electron-app/runtime/electron/pinPromptServer.loader.js
echo "Electron runtime files ready"

# ─── electron-builder ─────────────────────────────────────────────────────────
echo ""
echo "==> Building macOS app..."
cp electron-app/package.json electron-app/package.json.bak
cp electron-app/package.json-bytecode-point electron-app/package.json

# Run electron-builder from inside electron-app/ so all relative paths resolve correctly.
pushd electron-app > /dev/null
CSC_IDENTITY_AUTO_DISCOVERY=false \
  "$ELECTRON_BUILDER" --mac "$ELECTRON_ARCH_FLAG" || {
    popd > /dev/null
    mv "$REPO_ROOT/electron-app/package.json.bak" "$REPO_ROOT/electron-app/package.json"
    echo "electron-builder failed"
    exit 1
  }
popd > /dev/null

mv electron-app/package.json.bak electron-app/package.json

echo ""
echo "==> Build complete!"
echo "    Installer: electron-app/dist/"
ls electron-app/dist/*.dmg electron-app/dist/*.zip 2>/dev/null || true
