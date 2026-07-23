const { BrowserWindow, ipcMain, app } = require('electron');
const http = require('http');
const path = require('path');

const PROMPT_TIMEOUT_MS = 120000;

const pinPrompt = {
  server: null,
  port: null,
  token: null,
  ready: null,
  win: null,
  windowReady: null,
  activePrompt: null,
  logger: () => {},
};

let isAppQuitting = false;

function logPin(message) {
  pinPrompt.logger(`[pin ${new Date().toISOString()}] ${message}`);
}

function cryptoRandomToken(len = 32) {
  try { return require('crypto').randomBytes(len).toString('hex'); } catch { return String(Date.now()) + Math.random().toString(16).slice(2); }
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 64 * 1024) {
        reject(new Error('Body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (error) { reject(error); }
    });
    req.on('error', reject);
  });
}

function forceWindowFocus(window) {
  if (!window || window.isDestroyed()) return;
  try { if (app && app.focus) app.focus({ steal: true }); } catch {}
  try { window.setAlwaysOnTop(true, 'screen-saver'); } catch {}
  try { if (window.isMinimized()) window.restore(); } catch {}
  try { window.show(); } catch {}
  try { if (window.moveTop) window.moveTop(); } catch {}
  try { window.focus(); } catch {}
  try { window.webContents.focus(); } catch {}
  try { window.flashFrame(true); } catch {}
}

function settleActivePrompt(activePrompt, reason, value) {
  if (!activePrompt || pinPrompt.activePrompt !== activePrompt || activePrompt.settled) return false;

  activePrompt.settled = true;
  pinPrompt.activePrompt = null;
  if (activePrompt.timeout) clearTimeout(activePrompt.timeout);
  if (activePrompt.onSubmit) ipcMain.removeListener('pin:submit', activePrompt.onSubmit);
  if (activePrompt.onCancel) ipcMain.removeListener('pin:cancel', activePrompt.onCancel);
  if (activePrompt.response && activePrompt.onResponseClose) {
    activePrompt.response.removeListener('close', activePrompt.onResponseClose);
  }

  const window = pinPrompt.win;
  if (window && !window.isDestroyed()) {
    try { window.flashFrame(false); } catch {}
    try { window.setSkipTaskbar(true); } catch {}
    try { window.hide(); } catch {}
  }

  logPin(`prompt completed reason=${reason} ageMs=${Date.now() - activePrompt.startedAt}`);
  activePrompt.resolve(value);
  return true;
}

function cancelActivePrompt(reason) {
  return settleActivePrompt(pinPrompt.activePrompt, reason, undefined);
}

function discardPinWindow(reason) {
  cancelActivePrompt(reason);
  const window = pinPrompt.win;
  pinPrompt.win = null;
  pinPrompt.windowReady = null;
  if (window && !window.isDestroyed()) {
    try { window.destroy(); } catch {}
  }
}

function createPinWindow() {
  if (pinPrompt.win && !pinPrompt.win.isDestroyed() && pinPrompt.windowReady) {
    return pinPrompt.windowReady;
  }

  const window = new BrowserWindow({
    width: 460,
    height: 240,
    useContentSize: true,
    resizable: false,
    alwaysOnTop: true,
    acceptFirstMouse: true,
    focusable: true,
    modal: false,
    skipTaskbar: true,
    show: false,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });

  pinPrompt.win = window;
  const readyPromise = new Promise((resolve, reject) => {
    let readySettled = false;
    const finishReady = () => {
      if (readySettled) return;
      readySettled = true;
      try { window.center(); } catch {}
      logPin('window loaded and ready');
      resolve(window);
    };
    const failReady = (_event, errorCode, errorDescription) => {
      if (readySettled) return;
      readySettled = true;
      reject(new Error(`PIN window failed to load: ${errorDescription || errorCode || 'unknown error'}`));
    };

    window.webContents.once('did-finish-load', finishReady);
    window.webContents.once('did-fail-load', failReady);
    window.loadFile(resolvePinHtmlPath()).catch((error) => {
      if (readySettled) return;
      readySettled = true;
      reject(error);
    });
  });

  pinPrompt.windowReady = readyPromise.catch((error) => {
    logPin(`window readiness failed: ${error && error.message ? error.message : String(error)}`);
    discardPinWindow('window_load_failed');
    throw error;
  });

  window.on('close', (event) => {
    if (isAppQuitting) return;
    event.preventDefault();
    cancelActivePrompt('window_closed');
  });
  window.on('closed', () => {
    cancelActivePrompt('window_destroyed');
    if (pinPrompt.win === window) {
      pinPrompt.win = null;
      pinPrompt.windowReady = null;
    }
  });
  window.webContents.on('render-process-gone', (_event, details) => {
    logPin(`renderer gone reason=${details && details.reason ? details.reason : 'unknown'}`);
    discardPinWindow('renderer_gone');
  });
  window.on('unresponsive', () => {
    logPin('renderer became unresponsive');
    discardPinWindow('renderer_unresponsive');
  });

  return pinPrompt.windowReady;
}

async function ensurePinWindowReady() {
  if (isAppQuitting) throw new Error('Application is quitting');
  if (!pinPrompt.win || pinPrompt.win.isDestroyed() || !pinPrompt.windowReady) {
    logPin('creating hidden PIN window');
    return createPinWindow();
  }
  return pinPrompt.windowReady;
}

function activePromptIsHealthy() {
  const activePrompt = pinPrompt.activePrompt;
  if (!activePrompt || activePrompt.settled) return false;
  if (activePrompt.state === 'preparing') return true;
  const window = pinPrompt.win;
  return !!(window && !window.isDestroyed() && window.isVisible());
}

function resolvePinHtmlPath() {
  const candidates = [];
  try { candidates.push(path.join(app.getAppPath(), 'renderer', 'pin.html')); } catch {}
  candidates.push(path.join(__dirname, '..', 'renderer', 'pin.html'));
  candidates.push(path.join(__dirname, '..', '..', 'renderer', 'pin.html'));
  const resolved = candidates.find((candidate) => {
    try { return require('fs').existsSync(candidate); } catch { return false; }
  });
  if (!resolved) throw new Error(`PIN window file not found. Checked: ${candidates.join(', ')}`);
  return resolved;
}

function showPinDialog(message, response) {
  return new Promise((resolve) => {
    const activePrompt = {
      resolve,
      response,
      startedAt: Date.now(),
      state: 'preparing',
      settled: false,
      timeout: null,
      onSubmit: null,
      onCancel: null,
      onResponseClose: null,
    };
    pinPrompt.activePrompt = activePrompt;

    activePrompt.timeout = setTimeout(() => {
      settleActivePrompt(activePrompt, 'timeout', undefined);
    }, PROMPT_TIMEOUT_MS);

    activePrompt.onResponseClose = () => {
      if (response && !response.writableEnded) {
        settleActivePrompt(activePrompt, 'client_disconnected', undefined);
      }
    };
    if (response) response.once('close', activePrompt.onResponseClose);

    (async () => {
      try {
        const window = await ensurePinWindowReady();
        if (pinPrompt.activePrompt !== activePrompt || activePrompt.settled) return;

        activePrompt.onSubmit = (_event, pin) => settleActivePrompt(activePrompt, 'submitted', pin);
        activePrompt.onCancel = () => settleActivePrompt(activePrompt, 'cancelled', undefined);
        ipcMain.once('pin:submit', activePrompt.onSubmit);
        ipcMain.once('pin:cancel', activePrompt.onCancel);

        window.webContents.send('pin:reset');
        window.webContents.send('pin:set-message', String(message || 'Enter token PIN'));
        try { window.center(); } catch {}
        try { window.setSkipTaskbar(false); } catch {}
        activePrompt.state = 'visible';
        logPin(`showing window preparationMs=${Date.now() - activePrompt.startedAt}`);
        forceWindowFocus(window);
        setTimeout(() => {
          if (pinPrompt.activePrompt === activePrompt && !activePrompt.settled) forceWindowFocus(window);
        }, 60);
      } catch (error) {
        logPin(`unable to show window: ${error && error.message ? error.message : String(error)}`);
        settleActivePrompt(activePrompt, 'show_failed', undefined);
      }
    })();
  });
}

app.on('before-quit', () => {
  isAppQuitting = true;
  cancelActivePrompt('app_quit');
  const window = pinPrompt.win;
  pinPrompt.win = null;
  pinPrompt.windowReady = null;
  if (window && !window.isDestroyed()) {
    try { window.destroy(); } catch {}
  }
  if (pinPrompt.server) {
    try { pinPrompt.server.close(); } catch {}
    pinPrompt.server = null;
  }
});

function ensureReady({ log } = {}) {
  if (typeof log === 'function') pinPrompt.logger = log;
  if (pinPrompt.server && pinPrompt.port && pinPrompt.token && pinPrompt.windowReady) {
    return pinPrompt.windowReady.then(() => ({ port: pinPrompt.port, token: pinPrompt.token }));
  }
  if (pinPrompt.ready) return pinPrompt.ready;

  pinPrompt.ready = new Promise((resolve, reject) => {
    const token = cryptoRandomToken();
    const server = http.createServer(async (req, res) => {
      try {
        if (req.method !== 'POST' || req.url !== '/prompt-pin') {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, message: 'Not found' }));
          return;
        }

        const remote = (req.socket && req.socket.remoteAddress) || '';
        const isLocal = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
        const authorization = req.headers.authorization || '';
        if (!isLocal || !authorization.startsWith('Bearer ') || authorization.slice(7) !== pinPrompt.token) {
          logPin(`unauthorized request from ${remote}`);
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, message: 'Unauthorized' }));
          return;
        }

        if (pinPrompt.activePrompt) {
          if (activePromptIsHealthy()) {
            logPin(`concurrent request rejected state=${pinPrompt.activePrompt.state}`);
            if (pinPrompt.activePrompt.state === 'visible') forceWindowFocus(pinPrompt.win);
            res.writeHead(429, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, message: 'PIN prompt already active' }));
            return;
          }
          logPin('recovering stale active prompt');
          cancelActivePrompt('stale_recovered');
        }

        logPin(`request received from ${remote}`);
        const body = await readJson(req).catch(() => ({}));
        const hint = (body && body.message) || 'Enter token PIN';
        const pin = await showPinDialog(hint, res).catch(() => undefined);
        if (res.writableEnded || res.destroyed) return;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (pin === undefined) {
          res.end(JSON.stringify({ ok: false, canceled: true }));
        } else {
          res.end(JSON.stringify({ ok: true, pin: String(pin || '') }));
        }
      } catch (error) {
        cancelActivePrompt('server_error');
        if (!res.writableEnded && !res.destroyed) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, message: error.message }));
        }
      }
    });

    server.once('error', (error) => {
      pinPrompt.ready = null;
      reject(error);
    });
    server.listen(0, '127.0.0.1', async () => {
      pinPrompt.server = server;
      pinPrompt.port = server.address().port;
      pinPrompt.token = token;
      logPin(`prompt server listening on 127.0.0.1:${pinPrompt.port}`);
      try {
        await ensurePinWindowReady();
        resolve({ port: pinPrompt.port, token: pinPrompt.token });
      } catch (error) {
        try { server.close(); } catch {}
        pinPrompt.server = null;
        pinPrompt.port = null;
        pinPrompt.token = null;
        pinPrompt.ready = null;
        reject(error);
      }
    });
  });

  return pinPrompt.ready;
}

module.exports = { ensureReady };
