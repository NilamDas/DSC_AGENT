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
function resolveElectronBinary(appOutDir, platform, productName, executableName) {
  if (platform === 'win32') {
    return path.join(appOutDir, `${executableName}.exe`);
  }
  if (platform === 'darwin') {
    // macOS uses the productName (with spaces) as the .app and binary name
    const macName = productName;
    return path.join(appOutDir, `${macName}.app`, 'Contents', 'MacOS', macName);
  }
  // Linux — electron-builder uses the executableName (typically the package
  // "name" field, lowercased with underscores replaced by hyphens). We check
  // multiple candidates since it can differ from productName.
  const candidates = [
    path.join(appOutDir, executableName),
    path.join(appOutDir, executableName.replace(/_/g, '-')),
    productName.toLowerCase().replace(/\s+/g, '-'),
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

  // Skip fuses on macOS — modifying the binary invalidates its code signature
  // causing EXC_BAD_ACCESS (SIGKILL (Code Signature Invalid)) on macOS 26+.
  // Apple's own code signing provides sufficient protection on this platform.
  if (electronPlatformName === 'darwin') {
    console.log('[fuses] skipped on macOS');
    return;
  }
  const productName = context.packager.appInfo.productName;
  const executableName = context.packager.appInfo.executableName
    || context.packager.appInfo.sanitizedName
    || productName.toLowerCase().replace(/\s+/g, '-');
  console.log(`[fuses] executableName=${executableName} productName=${productName}`);
  const electronPath = resolveElectronBinary(appOutDir, electronPlatformName, productName, executableName);

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
