const { app, BrowserWindow, Tray, Menu, ipcMain, dialog, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
// Local PIN prompt micro-server (for per-sign PIN requests from the agent)
const { ensureReady: ensurePinPromptServerReady } = require('./pinPromptServer.loader.js');

// ---------------------------------------------------------------------------
// Chromium flag policy (safe-by-default for distribution across all Linux
// machines). We do NOT apply aggressive flags globally because they can cause
// unwanted side effects on machines with working GPUs, reduce security, or change
// rendering behaviour between Chromium versions.
//
//   Safe defaults (always on):
//     - disableHardwareAcceleration()  — prevents GPU-process crashes on VMs,
//       containers, and machines without working GPU drivers. For a tray
//       utility app the UI is simple, so software rendering is fine.
//
//   Auto-detected (applied only when needed):
//     - disable-dev-shm-usage           — only when /dev/shm is too small or
//       unavailable (containers, restricted systems).
//
//   Runtime fallback (applied only after a GPU-related renderer crash):
//     - use-gl=swiftshader              — software GL fallback
//     - disable-gpu-compositing         — in-process software compositor
//     - disable-features=VizDisplayCompositor — legacy compositor fallback
//
//   Opt-in via settings (CHROMIUM_FLAGS in settings.json) for power users:
//     - no-sandbox                      — reduces security, avoid unless needed
//     - disable-gpu-sandbox             — usually unnecessary
//     - enable-features=UseSkiaRenderer — changes rendering behaviour
//     - no-zygote                       — affects process startup/performance
// ---------------------------------------------------------------------------

// Default: hardware acceleration off. This is the single most reliable fix for
// GPU crashes on VMs/containers and is safe for a simple tray app. Users can
// opt back in via settings (CHROMIUM_FLAGS.disableHardwareAcceleration=false).
app.disableHardwareAcceleration();

// Read settings early (before app.whenReady) so flag decisions can be made.
function readEarlySettings() {
  try {
    const p = path.join(app.getPath('userData'), 'settings.json');
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch { return {}; }
}

function applyChromiumFlags() {
  const settings = readEarlySettings();
  const flags = settings.CHROMIUM_FLAGS || {};

  // --- Safe default: hardware acceleration off (opt-out via settings) -------
  if (flags.disableHardwareAcceleration === false) {
    // User explicitly opted back in — nothing to do (default is already off).
    // Note: app.disableHardwareAcceleration() was already called above; if the
    // user wants it on, we can't re-enable it after the fact. This is a
    // documented limitation — the flag must be set before app ready.
  }

  // --- Auto-detect /dev/shm -------------------------------------------------
  // In containers/VMs /dev/shm is often 64MB or missing, which causes a FATAL
  // Chromium renderer crash. Only apply the workaround when actually needed.
  if (process.platform === 'linux' && shouldDisableDevShm()) {
    app.commandLine.appendSwitch('disable-dev-shm-usage');
  }

  // --- Opt-in flags (power users only) --------------------------------------
  if (flags.noSandbox === true) {
    app.commandLine.appendSwitch('no-sandbox');
  }
  if (flags.disableGpuSandbox === true) {
    app.commandLine.appendSwitch('disable-gpu-sandbox');
  }
  if (flags.useSkiaRenderer === true) {
    app.commandLine.appendSwitch('enable-features', 'UseSkiaRenderer');
  }
  if (flags.noZygote === true) {
    app.commandLine.appendSwitch('no-zygote');
  }
}

function shouldDisableDevShm() {
  // Check if /dev/shm exists and is a directory.
  try {
    const stat = fs.statSync('/dev/shm');
    if (!stat.isDirectory()) return true; // missing
  } catch {
    return true; // stat failed — assume unavailable
  }

  // Determine the actual mount size. `stat.size` on the directory itself is
  // just the directory entry size (0 or a few bytes), NOT the tmpfs capacity.
  // Use `df -k` to get the real mount size in KB.
  try {
    const { execFileSync } = require('child_process');
    const out = execFileSync('df', ['-k', '/dev/shm'], { encoding: 'utf8', timeout: 3000 });
    const lines = out.trim().split('\n');
    if (lines.length >= 2) {
      const parts = lines[1].trim().split(/\s+/);
      // df -k output: Filesystem 1K-blocks Used Available Use% Mounted on
      const totalKb = parseInt(parts[1], 10);
      if (!isNaN(totalKb) && totalKb > 0) {
        // If the mount is smaller than 128MB, Chromium can crash.
        if (totalKb < 128 * 1024) return true;
        return false;
      }
    }
  } catch {
    // df failed — fall through to conservative check below.
  }

  // Fallback: if we can't determine the size, check /proc/mounts for a tmpfs
  // entry with a small size= option.
  try {
    const mounts = fs.readFileSync('/proc/mounts', 'utf8');
    const line = mounts.split('\n').find((l) => l.includes(' /dev/shm '));
    if (line) {
      const sizeMatch = line.match(/\bsize=(\d+)([kKmMgG]?)\b/);
      if (sizeMatch) {
        let size = parseInt(sizeMatch[1], 10);
        const unit = (sizeMatch[2] || '').toLowerCase();
        if (unit === 'k') size *= 1024;
        else if (unit === 'm') size *= 1024 * 1024;
        else if (unit === 'g') size *= 1024 * 1024 * 1024;
        if (size > 0 && size < 128 * 1024 * 1024) return true;
        return false;
      }
    }
  } catch {}

  // Conservative default: if we can't determine the size, assume it's fine
  // (most desktop Linux systems have a proper /dev/shm). Only containers/VMs
  // with restricted /dev/shm will hit the df check above.
  return false;
}

// Runtime fallback: if the renderer crashes with a GPU-related reason, apply
// software-rendering fallbacks dynamically. This keeps the app working on
// broken-GPU machines without forcing software rendering on everyone.
let gpuFallbackApplied = false;
function applyGpuFallbackFlags() {
  if (gpuFallbackApplied) return;
  gpuFallbackApplied = true;
  LOG('[chromium] GPU-related renderer crash detected — applying software rendering fallback');
  app.commandLine.appendSwitch('use-gl', 'swiftshader');
  app.commandLine.appendSwitch('disable-gpu-compositing');
  app.commandLine.appendSwitch('disable-features', 'VizDisplayCompositor');
}

applyChromiumFlags();

let tray = null;
let mainWindow = null;
let agentProc = null;
let stopRequested = false; // track user-initiated stop to suppress auto-restart
let mainWindowReady = false;
let pendingControlPanelShow = false;
let isQuitting = false;
let lastLogs = [];

// Log file written right next to the executable so you can find it easily
// e.g. C:\Users\Administrator\AppData\Local\Programs\dsc-agent-electron\electron.log
const LOG_FILE_PATH = (() => {
  try {
    // app.getPath('exe') returns the full path to the .exe — we write alongside it
    return path.join(path.dirname(app.getPath('exe')), 'electron.log');
  } catch {
    try {
      return path.join(app.getPath('userData'), 'electron.log');
    } catch {
      return path.join(require('os').tmpdir(), 'dsc-agent-electron.log');
    }
  }
})();

function writeToLogFile(line) {
  try {
    fs.appendFileSync(LOG_FILE_PATH, line + '\n', 'utf8');
  } catch {}
}

const LOG = (msg) => {
  const line = `[electron] ${msg}`;
  console.log(line);
  writeToLogFile(line);
  lastLogs.push(line);
  if (lastLogs.length > 2000) lastLogs.shift();
};

const { Notification } = require('electron');


app.setAppUserModelId('com.example.dscagent');
app.setName('DSC Agent');
function showTrayNotification(title, body) {
  try {
    console.log(`[notify] ${title}: ${body}`);
    // Use native Notification API (cross-platform, more reliable)
    const notification = new Notification({
      title: title || 'DSC Agent',
      body: body || '',
      icon: path.join(__dirname, '..', 'assets', 'icon.png')
    });
    notification.show();
  } catch (err) {
    LOG(`showTrayNotification failed: ${err && err.message ? err.message : String(err)}`);
  }
}

function userDataPath(...p) {
  return path.join(app.getPath('userData'), ...p);
}

function loadSettings() {
  try {
    const p = userDataPath('settings.json');
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch { return {}; }
}

function saveSettings(s) {
  const p = userDataPath('settings.json');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(s, null, 2));
}

function makeEnvFromSettings(settings) {
  const env = { ...process.env };
  const map = {
    PKCS11_DLL: 'PKCS11_DLL',
    DSC_AGENT_PORT: 'DSC_AGENT_PORT',
    ALLOW_ORIGINS: 'ALLOW_ORIGINS',
    DSC_AUTH_TOKEN: 'DSC_AUTH_TOKEN',
    DSC_SIGN_RECT: 'DSC_SIGN_RECT',
    DSC_REQUIRE_PIN_PER_SIGN: 'DSC_REQUIRE_PIN_PER_SIGN',
  };
  for (const k of Object.keys(map)) {
    if (settings[k]) env[map[k]] = String(settings[k]);
  }
  // Default to requiring PIN per sign if not explicitly configured
  if (!('DSC_REQUIRE_PIN_PER_SIGN' in settings)) {
    env.DSC_REQUIRE_PIN_PER_SIGN = env.DSC_REQUIRE_PIN_PER_SIGN || '1';
  }
  return env;
}

function getPort(settings) {
  const p = (settings.DSC_AGENT_PORT || '').trim();
  return p || '18080';
}

function resolveAgentEntry() {
  if (app.isPackaged) {
    const packaged = path.join(process.resourcesPath || '', 'agent', 'dsc-agent.loader.js');
    if (!fs.existsSync(packaged)) {
      throw new Error(`Packaged agent entry not found: ${packaged}`);
    }
    return packaged;
  }

  const dev = path.join(__dirname, '..', '..', 'dist', 'agent', 'dsc-agent.loader.js');
  if (!fs.existsSync(dev)) {
    throw new Error(`Development agent entry not found: ${dev}`);
  }
  return dev;
}

function resolveNodeBin() {
  const res = process.resourcesPath || '';
  const plat = process.platform;
  let candidate;
  if (plat === 'win32') candidate = path.join(res, 'bin', 'win', 'node.exe');
  else if (plat === 'darwin') candidate = path.join(res, 'bin', 'mac', 'node');
  else candidate = path.join(res, 'bin', 'linux', 'node');

  if (app.isPackaged) {
    if (candidate && fs.existsSync(candidate)) return candidate;
    throw new Error(`Bundled Node runtime not found: ${candidate}`);
  }

  if (candidate && fs.existsSync(candidate)) return candidate;
  return process.env.DSC_NODE_PATH || 'node';
}

async function startAgent() {
  showTrayNotification('DSC Agent', 'Agent starting...')
  if (agentProc) return;
  stopRequested = false; // clear any previous stop intent
  const agentPath = resolveAgentEntry();
  const settings = loadSettings();
  const env = makeEnvFromSettings(settings);
  // Always provide a local prompt server so clients can request tool-driven PIN entry per request
  const pinCfg = await ensurePinPromptServerReady({ getMainWindow: () => mainWindow, log: LOG });
  if (pinCfg && pinCfg.port && pinCfg.token) {
    env.DSC_PIN_PROMPT_URL = `http://127.0.0.1:${pinCfg.port}/prompt-pin`;
    env.DSC_PIN_PROMPT_TOKEN = pinCfg.token;
  }
  const nodeCmd = resolveNodeBin();
  LOG(`Starting agent: ${nodeCmd} ${agentPath}`);
  
  try {
    agentProc = spawn(nodeCmd, [agentPath], { env, windowsHide: true, cwd: path.dirname(path.dirname(agentPath)) });
    agentProc.stdout.on('data', d => { const s = String(d).trim(); if (s) LOG(`[agent] ${s}`); });
    agentProc.stderr.on('data', d => { const s = String(d).trim(); if (s) LOG(`[agent] ${s}`); });
    agentProc.on('exit', (code, signal) => {
      LOG(`[agent] exited code=${code} signal=${signal}`);
      try { showTrayNotification('DSC Agent', 'Agent Stopped'); } catch (e) {}
      agentProc = null;
      updateTrayMenu();
      const s = loadSettings();
      // If the user explicitly requested stop, do not auto-restart
      if (!stopRequested && s.AUTO_START === true) {
        // simple auto-restart guard
        setTimeout(() => {
          if (!agentProc) startAgent();
        }, 1500);
      }
      // Clear stop flag after a full exit cycle
      stopRequested = false;
    });
    updateTrayMenu();

  } catch (e) {
    LOG(`Failed to start agent: ${e.message || e}`);
    dialog.showErrorBox('DSC Agent', `Failed to start agent: ${e.message || e}`);
  }
}



 

function stopAgent() {
  if (!agentProc) return;
  stopRequested = true;
  try {
    // Try graceful termination first
    agentProc.kill();
  } catch {}
  // Fallback: if still alive after a short delay, force kill (especially on Windows)
  const pid = agentProc.pid;
  setTimeout(() => {
    if (agentProc) {
      if (process.platform === 'win32') {
        try {
          const { spawn } = require('child_process');
          spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true });
        } catch {}
      } else {
        try { agentProc.kill('SIGKILL'); } catch {}
      }
    }
  }, 800);
  updateTrayMenu();
}


// app icon path based on platform
function getAppIcon() {
  if (process.platform === 'win32') {
    return path.join(__dirname, 'assets', 'windows', 'icon.ico');
  }
  if (process.platform === 'darwin') {
    return path.join(__dirname, 'assets', 'mac', 'icon.icns');
  }
  return path.join(__dirname, 'assets', 'icon.png'); // linux
}


function createWindow() {
  LOG('createWindow called');
  if (mainWindow && !mainWindow.isDestroyed()) return mainWindow;
  mainWindowReady = false;
  pendingControlPanelShow = false;
  const iconPath = getAppIcon();
  LOG(`createWindow: resolved icon path is ${iconPath}`);
  mainWindow = new BrowserWindow({
    width: 820,
    height: 600,
    show: false,
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    }
  });

  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
    LOG(`[electron] did-fail-load: ${errorDescription} (${errorCode}) at ${validatedURL}`);
  });

  mainWindow.webContents.on('crashed', (event, killed) => {
    LOG(`[electron] renderer process crashed (killed=${killed})`);
  });

  mainWindow.webContents.on('render-process-gone', (event, details) => {
    LOG(`[electron] render process gone: reason=${details.reason} exitCode=${details.exitCode}`);
    // If the crash looks GPU-related (common in VMs/containers without working
    // GPU drivers), apply software-rendering fallback flags dynamically.
    if (details.reason === 'crashed' || details.reason === 'oom') {
      const exitCode = details.exitCode;
      // GPU process crashes often surface as exit codes 133 (SIGTRAP), 134
      // (SIGABRT), 135 (SIGBUS), 139 (SIGSEGV) or 6 (abort).
      const gpuLikeCodes = [6, 133, 134, 135, 139];
      if (gpuLikeCodes.includes(exitCode)) {
        applyGpuFallbackFlags();
      }
    }
    // Auto-recover from renderer crashes (common in software-rendering / safe
    // graphics mode). Reload the page so the control panel comes back.
    if (!isQuitting && details.reason === 'crashed') {
      LOG('[electron] renderer crashed — reloading window');
      setTimeout(() => {
        if (mainWindow && !mainWindow.isDestroyed()) {
          try { mainWindow.webContents.reload(); } catch {}
        }
      }, 500);
    }
  });

  mainWindow.webContents.on('console-message', (event, level, message, line, sourceId) => {
    LOG(`[renderer:${level}] ${message} (${sourceId}:${line})`);
  });

  mainWindow.on('unresponsive', () => {
    LOG('[electron] window became unresponsive');
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
  mainWindow.on('closed', () => {
    mainWindow = null;
    mainWindowReady = false;
  });
  mainWindow.once('ready-to-show', () => {
    LOG('[electron] ready-to-show event fired');
    mainWindowReady = true;
    if (pendingControlPanelShow) {
      pendingControlPanelShow = false;
      showControlPanel();
    }
  });

  // Fallback: if ready-to-show never fires (e.g. renderer is slow or crashed),
  // force-show the window after a timeout so the user isn't left with nothing.
  const readyFallbackTimer = setTimeout(() => {
    if (!mainWindowReady && mainWindow && !mainWindow.isDestroyed()) {
      LOG('[electron] ready-to-show fallback: forcing window show');
      mainWindowReady = true;
      mainWindow.show();
    }
  }, 4000);

  mainWindow.on('closed', () => {
    clearTimeout(readyFallbackTimer);
  });

  // Kick a repaint once the page finishes loading — helps in software-rendering
  // environments where the first paint can be skipped.
  mainWindow.webContents.on('did-finish-load', () => {
    LOG('[electron] did-finish-load fired');
    try {
      mainWindow.webContents.executeJavaScript(
        `document.body.style.display = 'none'; void document.body.offsetHeight; document.body.style.display = '';`
      ).catch(() => {});
    } catch {}
  });

  const htmlPath = path.join(__dirname, 'renderer', 'index.html');
  LOG(`createWindow: loading file ${htmlPath}`);
  mainWindow.loadFile(htmlPath);
  return mainWindow;
}


function showControlPanel() {
  LOG('showControlPanel called');
  const win = createWindow();
  if (!win || win.isDestroyed()) {
    LOG('showControlPanel: window is null or destroyed');
    return;
  }
  if (!mainWindowReady) {
    LOG('showControlPanel: window is not ready yet, deferring show');
    pendingControlPanelShow = true;
    return;
  }
  LOG('showControlPanel: showing window now');
  if (win.isMinimized()) win.restore();
  win.show();
  try { win.focus(); win.webContents.focus(); } catch {}
}

function configureAutoLaunch(settings) {
  const desired = settings && settings.AUTO_LAUNCH !== false;
  if (!desired) {
    if ((process.platform === 'darwin' || process.platform === 'win32') && app.isPackaged) {
      try { app.setLoginItemSettings({ openAtLogin: false }); } catch (err) { LOG(`Failed to disable auto-launch: ${err.message || err}`); }
    }
    return;
  }
  if (process.platform === 'win32' || process.platform === 'darwin') {
    if (!app.isPackaged) {
      LOG('[autoLaunch] Skipping login item registration in dev mode');
      
      return;
    }
    try {
      app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true, args: [] });
      LOG('[autoLaunch] Login item enabled');
    } catch (err) {
      LOG(`[autoLaunch] Failed to enable login item: ${err.message || err}`);
    }
  } else if (process.platform === "linux") {
    LOG('[autoLaunch] Configure your desktop environment to start the app at login (see README).');
  }
}
function updateTrayMenu() {
  if (!tray) return;
  const s = loadSettings();
  const url = `http://127.0.0.1:${getPort(s)}`;
  const menu = Menu.buildFromTemplate([
    { label: 'Open Control Panel', click: () => showControlPanel() },
    { type: 'separator' },
    { label: agentProc ? 'Stop Agent' : 'Start Agent', click: () => agentProc ? stopAgent() : startAgent() },
    { label: `Agent URL: ${url}`, enabled: false },
    { label: 'View Logs', click: () => dialog.showMessageBox({ type: 'info', title: 'DSC Agent Logs', message: lastLogs.slice(-100).join('\n') }) },
    { type: 'separator' },
    { label: 'Quit', role: 'quit' },
  ]);
  tray.setContextMenu(menu);
  tray.setToolTip(agentProc ? `DSC Agent (running on ${url})` : 'DSC Agent (stopped)');
}

// Fetch JSON or error from given URL in application menu
async function fetchJsonOrError(url) {
  try {
    const res = await fetch(url)

    const rawText = await res.text()
    let parsed = rawText

    try {
      parsed = JSON.parse(rawText)
    } catch {
      // non-JSON response (plain text / HTML)
    }

    if (!res.ok) {
      const body =
        typeof parsed === 'object'
          ? JSON.stringify(parsed, null, 2)
          : String(parsed)

      throw new Error(
        `HTTP ${res.status} ${res.statusText}\n\n${body}`
      )
    }

    return {
      ok: true,
      data: parsed
    }
  } catch (err) {
    return {
      ok: false,
      error: err.message || 'Unable to reach agent'
    }
  }
}




// custom application menu
function createAppMenu() {
  const template = [
    {
      label: 'File',
      submenu: [
        {
          label: agentProc ? 'Stop Agent' : 'Start Agent',
          click: () => agentProc ? stopAgent() : startAgent()
        },
        { type: 'separator' },
        { role: 'quit' }
      ]
    },

    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'close' }
      ]
    },

    {
      label: 'Tools',
      submenu: [
        {
          label: 'Dev Tools',
          submenu: [
            {
              label: 'Health Check',
              click: async () => {
                const s = loadSettings()
                const url = `http://127.0.0.1:${getPort(s)}/health`

                  const data = await fetchJsonOrError(url)
                  // dialog.showMessageBox({
                  //   type: 'info',
                  //   title: 'Agent Health',
                  //   message: JSON.stringify(data, null, 2)
                  // })
                  dialog.showMessageBox({
                    type: data.ok ? 'info' : 'error',
                    title: data.ok ? 'Agent Health' : 'Health Check Failed',
                    message: data.ok
                      ? JSON.stringify(data.data, null, 2)
                      : data.error
                  })
                
              }
            },

            {
              label: 'Certificates',
              click: async () => {
                const s = loadSettings()
                const url = `http://127.0.0.1:${getPort(s)}/certs`

                  const data = await fetchJsonOrError(url)
                  // dialog.showMessageBox({
                  //   type: 'info',
                  //   title: 'Certificates',
                  //   message: JSON.stringify(data, null, 2)
                  // })
                  dialog.showMessageBox({
                    type: data.ok ? 'info' : 'error',
                    title: data.ok ? 'Certificates' : 'Certificate Fetch Failed',
                    message: data.ok
                      ? JSON.stringify(data.data, null, 2)
                      : data.error
                  })
               
              }
            },

            {
              label: 'View Logs',
              click: () => {
                dialog.showMessageBox({
                  type: 'info',
                  title: 'DSC Agent Logs',
                  message: lastLogs.slice(-100).join('\n') || 'No logs available'
                })
              }
            }
          ]
        },

        { type: 'separator' },

        {
          label: 'Inspect',
          accelerator: 'CmdOrCtrl+Shift+I',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.toggleDevTools()
            }
          }
        }
      ]
    }
  ]

  Menu.setApplicationMenu(Menu.buildFromTemplate(template))
}



// single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
  process.exit(0);
}

app.on('second-instance', () => {
  // Someone tried to run a second instance — bring control panel to front
  showControlPanel();
});




app.whenReady().then(() => {

  createAppMenu();

  if (process.platform === 'darwin' && app.dock) {
    try { app.dock.hide(); } catch {}
  }

  // On macOS the tray icon must be a "template image" — a small monochrome
  // PNG whose name ends with "Template". This lets macOS adapt it to light/dark
  // menu bar automatically. Using a colour PNG causes it to be invisible or
  // missing on macOS 13+/Sequoia.
  let iconPath;
  if (process.platform === 'darwin') {
    // Prefer a dedicated 22x22 template icon; fall back to the 16x16 asset.
    const templatePath = path.join(__dirname, 'assets', 'Mac', 'iconTemplate.png');
    const fallbackPath = path.join(__dirname, 'assets', 'Mac', 'icon-16x16.png');
    iconPath = fs.existsSync(templatePath) ? templatePath : fallbackPath;
  } else {
    iconPath = path.join(__dirname, 'assets', 'icon.png');
  }

  let icon = fs.existsSync(iconPath) ? nativeImage.createFromPath(iconPath) : nativeImage.createEmpty();
  if (process.platform === 'darwin') {
    // macOS menu bar icons must be small (usually 16x16 or 22x22). 
    // If the provided image is larger (like a 512x512 app icon), it won't render in the menu bar.
    const size = icon.getSize();
    if (size.width > 22 || size.height > 22) {
      icon = icon.resize({ width: 16, height: 16 });
    }
    icon.setTemplateImage(true);
  }
  tray = new Tray(icon);
  updateTrayMenu();

  // Open control panel on left-click (Windows/Linux) or double-click
  tray.on('click', () => showControlPanel());
  tray.on('double-click', () => showControlPanel());

  // Pre-create the window hidden so the first open is instant
  createWindow();

  const s = loadSettings();
  configureAutoLaunch(s);
  if (s.AUTO_START !== false) { // default true
    startAgent();
  } else {
    LOG('AUTO_START disabled; agent will not start automatically');
    showTrayNotification('DSC Agent', 'Running in tray. Right-click the tray icon to start the agent.');
  }
});

app.on('window-all-closed', (e) => {
  if (!isQuitting) {
    // Keep running in tray
    e.preventDefault();
  }
});

app.on('activate', () => {
  showControlPanel();
});

app.on('before-quit', () => {
  isQuitting = true;
  // Forcefully kill the agent child process synchronously so no orphan remains
  if (agentProc) {
    const pid = agentProc.pid;
    try { agentProc.kill(); } catch {}
    if (process.platform === 'win32' && pid) {
      try {
        require('child_process').spawnSync(
          'taskkill', ['/PID', String(pid), '/T', '/F'],
          { windowsHide: true }
        );
      } catch {}
    }
    agentProc = null;
  }
  stopRequested = true;
  if (tray) {
    tray.destroy();
    tray = null;
  }
});

app.on('will-quit', () => {
  // Failsafe: if HTTP servers or timers keep the process alive, force-exit
  setTimeout(() => process.exit(0), 500);
});

// IPC
ipcMain.handle('settings:get', () => loadSettings());
ipcMain.handle('settings:set', (evt, s) => { saveSettings(s || {}); return { ok: true }; });
ipcMain.handle('agent:start', async () => { await startAgent(); return { ok: true }; });
ipcMain.handle('agent:stop', () => { stopAgent(); return { ok: true }; });
ipcMain.handle('logs:get', () => ({ ok: true, logs: lastLogs.slice(-500) }));

const INSTALLATION_GUIDE_NAME = 'DSC_AGENT_CLIENT_INSTALLATION_GUIDE.docx';

function resolveInstallationGuidePath() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'documents', INSTALLATION_GUIDE_NAME);
  }
  return path.join(__dirname, 'resources', 'documents', INSTALLATION_GUIDE_NAME);
}

ipcMain.handle('document:download-installation-guide', async () => {
  const sourcePath = resolveInstallationGuidePath();
  if (!fs.existsSync(sourcePath)) {
    LOG(`Client installation guide missing: ${sourcePath}`);
    return { ok: false, error: 'Client installation guide is not available.' };
  }

  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Download DSC Agent Client Installation Guide',
    defaultPath: path.join(app.getPath('downloads'), INSTALLATION_GUIDE_NAME),
    filters: [{ name: 'Microsoft Word Document', extensions: ['docx'] }],
  });
  if (result.canceled || !result.filePath) return { ok: false, canceled: true };

  try {
    await fs.promises.copyFile(sourcePath, result.filePath);
    LOG(`Client installation guide saved: ${result.filePath}`);
    return { ok: true, file: result.filePath };
  } catch (error) {
    LOG(`Client installation guide save failed: ${error && error.message ? error.message : String(error)}`);
    return { ok: false, error: error && error.message ? error.message : String(error) };
  }
});


ipcMain.handle('notify', (evt, title, body) => {
  try { showTrayNotification(title || 'DSC Agent', body || ''); } catch (e) { LOG(`notify failed: ${e && e.message ? e.message : e}`); }
  return { ok: true };
});

function dllPresetsForPlatform() {
  const p = process.platform;
  if (p === 'win32') {
    return [
      'C:/Windows/System32/SignatureP11.dll',
      'C:/Windows/SysWOW64/SignatureP11.dll',
      'C:/Windows/System32/eps2003csp11.dll',
      'C:/Windows/SysWOW64/eps2003csp11.dll',
      'C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
      'C:/Program Files (x86)/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
    ];
  } else if (p === 'darwin') {
    return [
      '/Library/OpenSC/lib/opensc-pkcs11.so',
      '/usr/local/lib/opensc-pkcs11.so',
      '/usr/local/lib/libeTPkcs11.dylib',
      '/Library/Frameworks/eToken.framework/Versions/Current/eToken',
    ];
  } else {
    // linux
    return [
      '/usr/lib/opensc-pkcs11.so',
      '/usr/local/lib/opensc-pkcs11.so',
      '/usr/lib64/opensc-pkcs11.so',
      '/usr/local/lib64/opensc-pkcs11.so',
      '/usr/lib/libeTPkcs11.so',
    ];
  }
}

ipcMain.handle('dll:presets', () => {
  const list = dllPresetsForPlatform().map(p => ({ path: p, exists: fs.existsSync(p) }));
  return { ok: true, presets: list };
});

ipcMain.handle('dll:browse', async () => {
  const filters = [];
  if (process.platform === 'win32') filters.push({ name: 'PKCS#11', extensions: ['dll'] });
  else if (process.platform === 'darwin') filters.push({ name: 'PKCS#11', extensions: ['so','dylib'] });
  else filters.push({ name: 'PKCS#11', extensions: ['so'] });
  const r = await dialog.showOpenDialog({ title: 'Select PKCS#11 Module', properties: ['openFile'], filters });
  if (r.canceled || !r.filePaths.length) return { ok: false, canceled: true };
  return { ok: true, file: r.filePaths[0] };
});
// PIN prompt server moved to ./main/pinPromptServer.js