'use strict';

/**
 * Linux sandbox compatibility detection for the DSC Agent Electron app.
 *
 * Security model (see task requirements):
 *   - Prefer the real Chromium/Electron sandbox (chrome-sandbox, SUID root, 4755).
 *   - .deb:  completes the AppArmor userns integration (separate profile) so the
 *            Chromium sandbox stays enabled on Ubuntu 24.04.
 *   - RPM:   sets chrome-sandbox to root:root / 4755 via post-install; does NOT
 *            touch AppArmor or SELinux.
 *   - AppImage: the SUID chrome-sandbox cannot be used; a *controlled, runtime
 *            only* `--no-sandbox` fallback is applied, with a clear log entry.
 *
 * This module NEVER permanently disables the sandbox, NEVER disables AppArmor
 * / SELinux / user namespaces globally, and NEVER modifies
 * /etc/apparmor.d/unprivileged_userns.
 */

const fs = require('fs');
const path = require('path');

function isRunningAsRoot() {
  try {
    return typeof process.getuid === 'function' && process.getuid() === 0;
  } catch {
    return false;
  }
}

function isAppImageRuntime() {
  return Boolean(process.env.APPIMAGE) || Boolean(process.env.APPDIR);
}

function resolveSandboxHelperPath() {
  try {
    return path.join(path.dirname(process.execPath), 'chrome-sandbox');
  } catch {
    return null;
  }
}

function statSandboxHelper(sandboxPath) {
  if (!sandboxPath) return null;
  try {
    const st = fs.statSync(sandboxPath);
    return {
      exists: true,
      owner: st.uid === 0 ? 'root' : String(st.uid),
      group: st.gid === 0 ? 'root' : String(st.gid),
      mode: (st.mode & 0o7777).toString(8).padStart(4, '0'),
    };
  } catch {
    return null;
  }
}

function isPackaged() {
  try {
    const { app } = require('electron');
    return Boolean(app && app.isPackaged);
  } catch {
    return false;
  }
}

function detectSandbox() {
  const info = {
    platform: process.platform,
    isPackaged: isPackaged(),
    isRoot: isRunningAsRoot(),
    isAppImage: isAppImageRuntime(),
    sandboxPath: resolveSandboxHelperPath(),
    helper: null,
    sandboxUsable: true,
    reason: 'ok',
  };

  if (info.platform !== 'linux') {
    info.reason = 'non-Linux platform (sandbox managed by OS)';
    return info;
  }

  if (!info.isPackaged) {
    info.reason = 'development mode (not packaged)';
    return info;
  }

  if (info.isRoot) {
    info.sandboxUsable = false;
    info.reason = 'running as root (Chromium refuses sandbox)';
    return info;
  }

  if (info.isAppImage) {
    info.sandboxUsable = false;
    info.reason = 'AppImage environment (SUID chrome-sandbox not usable)';
    return info;
  }

  info.helper = statSandboxHelper(info.sandboxPath);
  if (!info.helper) {
    info.sandboxUsable = false;
    info.reason = 'chrome-sandbox helper missing: ' + info.sandboxPath;
    return info;
  }

  const isSuiRoot = info.helper.owner === 'root' &&
    (parseInt(info.helper.mode, 8) & 0o4000) !== 0;

  if (!isSuiRoot) {
    info.sandboxUsable = false;
    info.reason = 'chrome-sandbox helper not SUID root';
    return info;
  }

  info.reason = 'chrome-sandbox present (' + info.helper.owner + ':' + info.helper.group + ' ' + info.helper.mode + ')';
  return info;
}

function relaunchWithoutSandboxIfNeeded() {
  // Chromium's "Running as root without --no-sandbox is not supported" check
  // happens in native startup code BEFORE any JavaScript runs. Appending the
  // switch via app.commandLine is therefore too late for the root case.
  // The only reliable fix is to re-exec this very executable with
  // `--no-sandbox` on the real command line (runtime-only, nothing persisted).
  if (process.platform !== 'linux') return false;
  if (!isRunningAsRoot()) return false;
  if (process.argv.includes('--no-sandbox')) return false;

  const { spawn } = require('child_process');
  const args = process.argv.slice(1).concat(['--no-sandbox']);
  console.log('[linux-sandbox] running as root -> relaunching with --no-sandbox');
  const child = spawn(process.execPath, args, {
    stdio: 'inherit',
    env: Object.assign({}, process.env, { ELECTRON_ENABLE_LOGGING: '1' }),
  });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    else process.exit(code == null ? 0 : code);
  });
  child.on('error', (err) => {
    console.error('[linux-sandbox] relaunch failed:', err);
    process.exit(1);
  });
  return true;
}

function applyLinuxSandboxStrategy(appendSwitch) {
  const info = detectSandbox();

  if (process.platform !== 'linux') {
    return info;
  }

  const log = (line) => { try { console.log('[linux-sandbox] ' + line); } catch {} };

  if (info.sandboxUsable) {
    log('Chromium sandbox OK: ' + info.reason);
    return info;
  }

  if (info.isRoot) {
    // Must go through a real re-exec (see relaunchWithoutSandboxIfNeeded).
    relaunchWithoutSandboxIfNeeded();
    return info;
  }

  log('Chromium sandbox unavailable: ' + info.reason);
  log('Using runtime-only compatibility fallback (--no-sandbox)');
  if (typeof appendSwitch === 'function') {
    try { appendSwitch('no-sandbox'); } catch {}
  }
  return info;
}

module.exports = {
  detectSandbox,
  applyLinuxSandboxStrategy,
  isRunningAsRoot,
  isAppImageRuntime,
  relaunchWithoutSandboxIfNeeded,
};