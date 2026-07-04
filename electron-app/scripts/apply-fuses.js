'use strict';
/**
 * electron-builder afterPack hook — flips Electron fuses on the packaged binary.
 *
 * Fuses permanently disable dangerous runtime switches so no attacker can:
 *   - Run `DSC Agent.exe --run-as-node` to use it as a plain Node runtime
 *   - Attach a debugger via `--inspect` / `--inspect-brk`
 *   - Inject code via the NODE_OPTIONS environment variable
 *
 * References:
 *   https://www.electronjs.org/docs/latest/tutorial/fuses
 *   https://github.com/electron/fuses
 */

const path = require('path');
const fs = require('fs');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

/**
 * Returns the absolute path to the Electron executable inside the packed output.
 */
function resolveElectronBinary(appOutDir, platform, productName) {
  if (platform === 'win32') {
    return path.join(appOutDir, `${productName}.exe`);
  }
  if (platform === 'darwin') {
    return path.join(appOutDir, `${productName}.app`, 'Contents', 'MacOS', productName);
  }
  // Linux — electron-builder lowercases and replaces spaces with hyphens
  const linuxName = productName.toLowerCase().replace(/\s+/g, '-');
  const candidates = [
    path.join(appOutDir, linuxName),
    path.join(appOutDir, productName),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return candidates[0]; // let flipFuses report the missing-file error
}

/** electron-builder calls this after packing, before creating the installer. */
exports.default = async function afterPack(context) {
  const { appOutDir, electronPlatformName } = context;
  const productName = context.packager.appInfo.productName;
  const electronPath = resolveElectronBinary(appOutDir, electronPlatformName, productName);

  if (!fs.existsSync(electronPath)) {
    console.warn(`[fuses] binary not found at ${electronPath} — skipping`);
    return;
  }

  console.log(`[fuses] applying to ${electronPath}`);

  await flipFuses(electronPath, {
    version: FuseVersion.V1,
    // Prevent running the app binary as a plain Node.js runtime
    [FuseV1Options.RunAsNode]: false,
    // Prevent --inspect / --inspect-brk debugger attach
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    // Prevent code injection via NODE_OPTIONS environment variable
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  });

  console.log('[fuses] done');
};
