#!/usr/bin/env bash
# build-linux.sh — Linux equivalent of build-mac.sh / build-protected.ps1
# Run from the repo root: bash build-linux.sh
# Produces a protected (obfuscated) AppImage, .deb, and .rpm in electron-app/dist/
#
# Differences from Windows build:
#   - Downloads a portable Node 18 matching Electron's bundled Node version
#   - Uses that Node for esbuild, obfuscator, and bytenode (avoids system Node mismatch)
#   - Agent runs as obfuscated JS (not bytecode) so it works across different
#     Node/V8 versions (Node 26 in dev, bundled Node 18 in production)
#   - Electron files run as obfuscated JS (not bytecode) because Electron's V8
#     differs from Node 18's V8 (cachedDataRejected error)
#   - Produces AppImage, .deb, and .rpm for Linux

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# ─── Never build as root ───────────────────────────────────────────────────────
# Building as root makes dist/, build-artifacts/, runtime/, etc. owned by root,
# which then breaks later non-root builds and installs. Refuse loudly.
if [ "$(id -u)" = "0" ]; then
  echo "ERROR: do not run this build as root." >&2
  echo "       Run it as your normal user:  bash build-linux.sh" >&2
  exit 1
fi

# Recover from a previous root-owned build (e.g. someone ran it with sudo):
# hand the tree back to the current user so npm/esbuild/electron-builder work.
if ! [ -w "$REPO_ROOT/electron-app" ] || \
   find "$REPO_ROOT/build-artifacts" "$REPO_ROOT/electron-app/dist" \
        "$REPO_ROOT/electron-app/build-artifacts" "$REPO_ROOT/electron-app/runtime" \
        -user root -print -quit 2>/dev/null | grep -q .; then
  echo "==> Fixing ownership of previously root-owned build outputs..."
  sudo -n chown -R "$(id -u):$(id -g)" \
    "$REPO_ROOT/build-artifacts" "$REPO_ROOT/electron-app/dist" \
    "$REPO_ROOT/electron-app/build-artifacts" "$REPO_ROOT/electron-app/runtime" \
    2>/dev/null || {
      echo "ERROR: build outputs are root-owned and could not be fixed automatically." >&2
      echo "       Run:  sudo chown -R $(id -u):$(id -g) '$REPO_ROOT/build-artifacts' '$REPO_ROOT/electron-app/dist' '$REPO_ROOT/electron-app/build-artifacts' '$REPO_ROOT/electron-app/runtime'" >&2
      exit 1
    }
fi

# ─── Config ────────────────────────────────────────────────────────────────────
NODE_VERSION="18.20.4"          # Must match Electron's bundled Node version
BUILD_ARCH="$(uname -m)"        # Current build machine arch: x86_64 or aarch64

case "$BUILD_ARCH" in
  x86_64) NODE_ARCH="x64"; ELECTRON_ARCH_FLAG="--x64" ;;
  aarch64|arm64) NODE_ARCH="arm64"; ELECTRON_ARCH_FLAG="--arm64" ;;
  *)      echo "Unsupported architecture: $BUILD_ARCH"; exit 1 ;;
esac

NODE_DIR="$REPO_ROOT/electron-app/bin/linux"
NODE_BIN="$NODE_DIR/node"
NODE_TAR="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.gz"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TAR}"

# ─── Dependency checks ─────────────────────────────────────────────────────────
echo ""
echo "==> Checking dependencies..."
ROOT_ESBUILD="$REPO_ROOT/electron-app/node_modules/.bin/esbuild"
ROOT_OBFUSCATOR="$REPO_ROOT/electron-app/node_modules/.bin/javascript-obfuscator"
ELECTRON_BUILDER="$REPO_ROOT/electron-app/node_modules/.bin/electron-builder"

for f in "$ROOT_ESBUILD" "$ROOT_OBFUSCATOR" "$ELECTRON_BUILDER"; do
  if [ ! -f "$f" ]; then
    echo "Missing: $f"
    echo "Run:  npm install && cd electron-app && npm install"
    exit 1
  fi
done

# ─── Clean stale build artifacts ───────────────────────────────────────────────
echo ""
echo "==> Cleaning stale build artifacts..."
rm -rf build-artifacts dist/agent
rm -rf electron-app/build-artifacts electron-app/runtime/electron
rm -rf electron-app/dist/linux-unpacked
rm -f electron-app/dist/*.AppImage electron-app/dist/*.deb electron-app/dist/*.rpm
rm -f electron-app/dist/builder-debug.yml electron-app/dist/builder-effective-config.yaml
mkdir -p build-artifacts dist/agent
mkdir -p electron-app/build-artifacts electron-app/runtime/electron

# ─── Resolve Node binary ───────────────────────────────────────────────────────
# Always download a portable Node 18 matching Electron's bundled Node version.
# The portable build is statically linked, so it can be copied into the app
# without missing shared libraries.
echo ""
echo "==> Resolving Node ${NODE_VERSION} (${NODE_ARCH})..."

mkdir -p "$NODE_DIR"
if [ -f "$NODE_BIN" ]; then
  NODE_FILE_INFO="$(file "$NODE_BIN" 2>/dev/null || true)"
  if [ "$NODE_ARCH" = "arm64" ] && ! echo "$NODE_FILE_INFO" | grep -qi "aarch64\|arm64"; then
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
  tar -xzf "/tmp/${NODE_TAR}" -C "$NODE_DIR" --strip-components=2 "node-v${NODE_VERSION}-linux-${NODE_ARCH}/bin/node"
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

# ─── Agent: bundle → obfuscate ────────────────────────────────────────────────
# NOTE: esbuild is a compiled Go binary — run it directly, NOT through $NODE_BIN
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
echo "==> Building Linux app (AppImage, deb, rpm)..."
cp electron-app/package.json electron-app/package.json.bak
cp electron-app/package.json-bytecode-point electron-app/package.json

# Run electron-builder from inside electron-app/ so all relative paths resolve correctly.
#
# NOTE: electron-builder's CLI has a `#!/usr/bin/env node` shebang. On machines
# without a system-wide Node (or when run under sudo, which strips nvm paths),
# `/usr/bin/env node` fails with "node: No such file or directory". We therefore
# invoke the CLI explicitly through the portable Node 18 downloaded above, and
# prepend its directory to PATH so any spawned helper scripts resolve it too.
pushd electron-app > /dev/null
env -u ELECTRON_RUN_AS_NODE \
  PATH="$NODE_DIR:$PATH" \
  CSC_IDENTITY_AUTO_DISCOVERY=false \
    "$NODE_BIN" "$ELECTRON_BUILDER" --linux "$ELECTRON_ARCH_FLAG" || {
  popd > /dev/null
  mv "$REPO_ROOT/electron-app/package.json.bak" "$REPO_ROOT/electron-app/package.json"
  echo "electron-builder failed"
  exit 1
}
popd > /dev/null

mv electron-app/package.json.bak electron-app/package.json

# ─── Post-build fixes ─────────────────────────────────────────────────────────
echo ""
echo "==> Applying post-build fixes..."

# Fix chrome-sandbox permissions (required for Chromium sandbox on Linux).
# The sandbox helper must be owned by root and setuid (4755). A failure here is
# a security-relevant setup problem and must surface loudly, not be swallowed.
SANDBOX_BIN="$REPO_ROOT/electron-app/dist/linux-unpacked/chrome-sandbox"
if [ -f "$SANDBOX_BIN" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    chown root:root "$SANDBOX_BIN"
    chmod 4755 "$SANDBOX_BIN"
  else
    echo "    (not root — cannot chown chrome-sandbox; relying on SUID bit)"
  fi
  OWNER="$(stat -c '%U' "$SANDBOX_BIN")"
  MODE="$(stat -c '%a' "$SANDBOX_BIN")"
  echo "    chrome-sandbox: owner=${OWNER} mode=${MODE}"
  if [ "${OWNER}" != "root" ] || [ "${MODE}" != "4755" ]; then
    # If we are root we just set 4755 above, so a mismatch means a real failure.
    # If we are NOT root, the in-tree mode is allowed to be 0644 — the DEB/RPM
    # post-install script (which runs as root on the target host) applies SUID.
    if [ "$(id -u)" -eq 0 ]; then
      echo "ERROR: chrome-sandbox must be root:root with mode 4755 (got owner=${OWNER} mode=${MODE})." >&2
      exit 1
    else
      echo "    WARNING: chrome-sandbox is owner=${OWNER} mode=${MODE} (expected root:root 4755)." >&2
      echo "    SUID will be applied by the DEB/RPM post-install on the target host." >&2
    fi
  fi
fi

# Ensure the main binary is executable
MAIN_BIN="$REPO_ROOT/electron-app/dist/linux-unpacked/dsc-agent-electron"
if [ -f "$MAIN_BIN" ]; then
  chmod +x "$MAIN_BIN"
  echo "    Main binary executable: $MAIN_BIN"
fi

# Ensure the bundled Node runtime is executable
NODE_RUNTIME="$REPO_ROOT/electron-app/dist/linux-unpacked/resources/bin/linux/node"
if [ -f "$NODE_RUNTIME" ]; then
  chmod +x "$NODE_RUNTIME"
  echo "    Bundled Node runtime executable: $NODE_RUNTIME"
fi

# Ensure AppImage is executable
for appimage in "$REPO_ROOT"/electron-app/dist/*.AppImage; do
  if [ -f "$appimage" ]; then
    chmod +x "$appimage"
    echo "    AppImage executable: $(basename "$appimage")"
  fi
done

# ─── Verification ─────────────────────────────────────────────────────────────
echo ""
echo "==> Verifying build output..."
UNPACKED_DIR="$REPO_ROOT/electron-app/dist/linux-unpacked"
if [ ! -d "$UNPACKED_DIR" ]; then
  echo "ERROR: linux-unpacked directory not found!"
  exit 1
fi

# Verify key files exist
REQUIRED_FILES=(
  "$UNPACKED_DIR/dsc-agent-electron"
  "$UNPACKED_DIR/resources/app.asar"
  "$UNPACKED_DIR/resources/agent/dsc-agent.loader.js"
  "$UNPACKED_DIR/resources/agent/dsc-agent.obf.js"
  "$UNPACKED_DIR/resources/agent/dsc-agent.config.json"
  "$UNPACKED_DIR/resources/agent/node_modules/pkcs11js/build/Release/pkcs11.node"
  "$UNPACKED_DIR/resources/bin/linux/node"
  "$UNPACKED_DIR/resources/documents/DSC_AGENT_CLIENT_INSTALLATION_GUIDE.docx"
)

for f in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: Missing required file: $f"
    exit 1
  fi
done
echo "    All required files present."

# Verify chrome-sandbox is SUID root in the unpacked tree (security-critical).
UNPACKED_SANDBOX="${UNPACKED_DIR}/chrome-sandbox"
if [ -f "${UNPACKED_SANDBOX}" ]; then
  SMODE="$(stat -c '%a' "${UNPACKED_SANDBOX}")"
  SOWN="$(stat -c '%U:%G' "${UNPACKED_SANDBOX}")"
  if [ "${SMODE}" != "4755" ] || [ "${SOWN}" != "root:root" ]; then
    echo "WARNING: unpacked chrome-sandbox is ${SOWN} ${SMODE} (expected root:root 4755)." >&2
    echo "         The DEB/RPM post-install scripts will fix this at install time." >&2
  else
    echo "    chrome-sandbox (unpacked): root:root 4755 OK"
  fi
fi

# Verify the AppArmor profile is embedded in the DEB post-install script.
# (The profile is intentionally NOT a packaged resource so the RPM/AppImage
# carry no AppArmor files; only the .deb installs/writes it into /etc/apparmor.d.)
DEB_POSTINST="$REPO_ROOT/electron-app/scripts/linux/after-install-deb.sh"
if [ ! -f "${DEB_POSTINST}" ]; then
  echo "ERROR: DEB post-install script missing: ${DEB_POSTINST}" >&2
  exit 1
fi
if ! grep -q 'userns,' "${DEB_POSTINST}"; then
  echo "ERROR: AppArmor profile (userns rule) not embedded in DEB post-install: ${DEB_POSTINST}" >&2
  exit 1
fi
echo "    AppArmor profile embedded in DEB post-install script."

# Verify asar contains the runtime files
if command -v npx > /dev/null 2>&1; then
  ASAR_LIST=$(cd electron-app && npx asar list dist/linux-unpacked/resources/app.asar 2>/dev/null || true)
  for entry in "/runtime/electron/main.loader.js" "/runtime/electron/main.obf.js" "/runtime/electron/preload.obf.js" "/renderer/index.html" "/assets/icon.png"; do
    if ! echo "$ASAR_LIST" | grep -q "$entry"; then
      echo "ERROR: app.asar missing: $entry"
      exit 1
    fi
  done
  echo "    app.asar contents verified."
fi

echo ""
echo "==> Build complete!"
echo "    Installers: electron-app/dist/"
ls electron-app/dist/*.AppImage electron-app/dist/*.deb electron-app/dist/*.rpm 2>/dev/null || true
echo ""
echo "    To run the unpacked build:"
echo "      electron-app/dist/linux-unpacked/dsc-agent-electron"
echo ""
echo "    If you get a sandbox error, run:"
echo "      sudo chown root:root electron-app/dist/linux-unpacked/chrome-sandbox"
echo "      sudo chmod 4755 electron-app/dist/linux-unpacked/chrome-sandbox"
echo ""
echo "    If the AppImage fails with 'libfuse.so.2' error, either:"
echo "      - Install libfuse2:  sudo apt install libfuse2"
echo "      - Or extract and run:  './dsc-agent-0.1.1.AppImage' --appimage-extract-and-run"
echo "    The .deb and .rpm installers do NOT require FUSE."
