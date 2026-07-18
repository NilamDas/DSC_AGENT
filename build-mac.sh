#!/usr/bin/env bash
# build-mac.sh — Mac equivalent of build-protected.ps1
# Run from the repo root: bash build-mac.sh
# Produces a protected (obfuscated) DMG in electron-app/dist/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

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

echo ""
echo "==> Preparing output directories..."
mkdir -p build-artifacts dist/agent
mkdir -p electron-app/build-artifacts electron-app/runtime/electron

echo ""
echo "==> Provisioning bundled Node runtime..."
mkdir -p electron-app/bin/mac
cp "$(command -v node)" electron-app/bin/mac/node

# ─── Agent: bundle → obfuscate ────────────────────────────────────────────────
echo ""
echo "==> Bundling agent..."
"$ROOT_ESBUILD" agent/dsc-agent.js \
  --bundle --platform=node --format=cjs --target=node18 \
  --external:pkcs11js \
  --outfile=build-artifacts/dsc-agent.bundle.js

echo ""
echo "==> Obfuscating agent..."
"$ROOT_OBFUSCATOR" build-artifacts/dsc-agent.bundle.js \
  --output build-artifacts/dsc-agent.obf.js \
  --target node --compact true \
  --identifier-names-generator hexadecimal \
  --rename-globals false --simplify true \
  --string-array true --string-array-encoding base64 \
  --string-array-threshold 0.75 \
  --unicode-escape-sequence false

# Agent runtime: use obf.js directly (no bytecode — arch-independent)
cp build-artifacts/dsc-agent.obf.js dist/agent/dsc-agent.obf.js
printf "require('./dsc-agent.obf.js');\n" > dist/agent/dsc-agent.loader.js
echo "Agent runtime files ready"

# ─── Electron: stage PIN source (path fix for bytecode context) ───────────────
echo ""
echo "==> Staging Electron sources..."
node -e "
  const fs = require('fs');
  let src = fs.readFileSync('electron-app/main/pinPromptServer.js', 'utf8');
  src = src.replace(
    \"require('path').join(__dirname, '..', 'renderer', 'pin.html')\",
    \"require('path').join(__dirname, '..', '..', 'renderer', 'pin.html')\"
  );
  fs.writeFileSync('electron-app/build-artifacts/pinPromptServer.bytecode-point.js', src, 'ascii');
"

# ─── Electron: bundle ─────────────────────────────────────────────────────────
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

# ─── Electron: obfuscate ──────────────────────────────────────────────────────
echo ""
echo "==> Obfuscating Electron files..."
for module in main pinPromptServer preload; do
  "$ROOT_OBFUSCATOR" "electron-app/build-artifacts/${module}.bundle.js" \
    --output "electron-app/build-artifacts/${module}.obf.js" \
    --target node --compact true \
    --identifier-names-generator hexadecimal \
    --rename-globals false --simplify true \
    --string-array true --string-array-encoding base64 \
    --string-array-threshold 0.75 \
    --unicode-escape-sequence false
done

# Electron runtime: use obf.js directly (no arch-specific bytecode)
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

CSC_IDENTITY_AUTO_DISCOVERY=false \
  "$ELECTRON_BUILDER" --mac --projectDir electron-app || {
    mv electron-app/package.json.bak electron-app/package.json
    echo "electron-builder failed"
    exit 1
  }

mv electron-app/package.json.bak electron-app/package.json

echo ""
echo "==> Build complete!"
echo "    Installer: electron-app/dist/"
ls electron-app/dist/*.dmg electron-app/dist/*.zip 2>/dev/null || true
