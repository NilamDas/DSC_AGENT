const { BrowserWindow, ipcMain, app } = require('electron');
const http = require('http');

let pinPrompt = { server: null, port: null, token: null, ready: null, busy: false, win: null, busyTimer: null };

// Set/clear busy with a 90-second safety auto-reset so one bad cycle never
// leaves the flag permanently true.
function setBusy(busy) {
  if (pinPrompt.busyTimer) { clearTimeout(pinPrompt.busyTimer); pinPrompt.busyTimer = null; }
  pinPrompt.busy = busy;
  if (busy) {
    pinPrompt.busyTimer = setTimeout(() => {
      pinPrompt.busy = false;
      pinPrompt.busyTimer = null;
      try { if (pinPrompt.win && !pinPrompt.win.isDestroyed()) pinPrompt.win.hide(); } catch {}
    }, 90000);
  }
}

function cryptoRandomToken(len = 32) {
  try { return require('crypto').randomBytes(len).toString('hex'); } catch { return String(Date.now()) + Math.random().toString(16).slice(2); }
}


function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; if (data.length > 64 * 1024) { reject(new Error('Body too large')); req.destroy(); } });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

// Aggressively bring a BrowserWindow to the front, stealing focus from the OS.
function forceWindowFocus(w) {
  if (!w || w.isDestroyed()) return;
  try { if (app && app.focus) app.focus({ steal: true }); } catch {}
  try { w.setAlwaysOnTop(true, 'screen-saver'); } catch {}
  try { if (w.isMinimized()) w.restore(); } catch {}
  try { w.show(); } catch {}
  try { if (w.moveTop) w.moveTop(); } catch {}
  try { w.focus(); } catch {}
  try { w.webContents.focus(); } catch {}
  try { w.flashFrame(true); } catch {}
}

// Pre-create the PIN window once at startup and keep it hidden so it loads in
// the background. When a sign request arrives we just show() it — near-instant
// with no BrowserWindow creation / HTML parse delay (was 3-4 s).
// It is NOT given a parent so it is a top-level window; this avoids the Windows
// foreground-lock issue that prevented it from stealing focus when the control
// panel was the active window.
function prewarmPinWindow() {
  if (pinPrompt.win && !pinPrompt.win.isDestroyed()) return;
  try {
    const w = new BrowserWindow({
      width: 460,
      height: 240,
      useContentSize: true,
      resizable: false,
      alwaysOnTop: true,
      acceptFirstMouse: true,
      focusable: true,
      modal: false,
      skipTaskbar: true,   // hidden from taskbar until shown
      show: false,
      webPreferences: { nodeIntegration: true, contextIsolation: false }
    });
    pinPrompt.win = w;
    w.loadFile(require('path').join(__dirname, '..', 'renderer', 'pin.html'));
    w.once('ready-to-show', () => { try { w.center(); } catch {} });
    // Intercept the close event (Alt-F4, window X button) — hide and cancel
    // instead of destroying so the window stays pre-warmed for next time.
    w.on('close', (e) => {
      e.preventDefault();
      try { w.setSkipTaskbar(true); } catch {}
      try { w.hide(); } catch {}
      if (pinPrompt.busy) {
        setBusy(false);
        // Synthetic cancel — unblock any waiting IPC listeners
        ipcMain.emit('pin:cancel');
      }
    });
  } catch {}
}

async function showPinDialog(message) {
  return new Promise((resolve) => {
    try {
      const w = pinPrompt.win;
      if (!w || w.isDestroyed()) { resolve(undefined); return; }

      // Clear previous input and set the new message before making the window visible.
      try { w.webContents.send('pin:reset'); } catch {}
      try { w.webContents.send('pin:set-message', String(message || 'Enter token PIN')); } catch {}

      let settled = false;
      const settle = (val) => { if (!settled) { settled = true; resolve(val); } };
      const cleanup = () => {
        ipcMain.removeListener('pin:submit', onSubmit);
        ipcMain.removeListener('pin:cancel', onCancel);
        try { w.setSkipTaskbar(true); } catch {}
        try { if (!w.isDestroyed()) w.hide(); } catch {}
      };
      const onSubmit = (evt, pin) => { cleanup(); settle(pin); };
      const onCancel = () => { cleanup(); settle(undefined); };
      ipcMain.once('pin:submit', onSubmit);
      ipcMain.once('pin:cancel', onCancel);

      try { w.center(); } catch {}
      try { w.setSkipTaskbar(false); } catch {}
      forceWindowFocus(w);
      // One follow-up focus pulse in case the OS blocked the first attempt.
      setTimeout(() => { forceWindowFocus(w); }, 60);
    } catch {
      resolve(undefined);
    }
  });
}

function ensureReady({ getMainWindow, log } = {}) {
  if (pinPrompt.server && pinPrompt.port && pinPrompt.token) return Promise.resolve({ port: pinPrompt.port, token: pinPrompt.token });
  if (pinPrompt.ready) return pinPrompt.ready;
  const logger = typeof log === 'function' ? log : () => {};
  pinPrompt.ready = new Promise((resolve) => {
    const token = cryptoRandomToken();
    const srv = http.createServer(async (req, res) => {
      try {
        if (req.method === 'POST' && req.url === '/prompt-pin') {
          const remote = (req.socket && req.socket.remoteAddress) || '';
          const isLocal = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
          const auth = req.headers['authorization'] || '';
          if (!isLocal || !auth.startsWith('Bearer ') || auth.slice(7) !== pinPrompt.token) {
            logger(`[pin] unauthorized attempt from ${remote}`);
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, message: 'Unauthorized' }));
            return;
          }
          if (pinPrompt.busy) {
            // Auto-recover if the window was hidden/destroyed while busy was still set.
            const gone = !pinPrompt.win || pinPrompt.win.isDestroyed() || !pinPrompt.win.isVisible();
            if (gone) {
              logger('[pin] busy flag stuck (window not visible), auto-recovering');
              setBusy(false);
              if (!pinPrompt.win || pinPrompt.win.isDestroyed()) prewarmPinWindow();
            } else {
              logger('[pin] prompt already active');
              res.writeHead(429, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ ok: false, message: 'PIN prompt already active' }));
              return;
            }
          }
          logger(`[pin] request received from ${remote}`);
          setBusy(true);
          const body = await readJson(req).catch(() => ({}));
          const hint = (body && body.message) || 'Enter token PIN';
          const pin = await showPinDialog(hint).catch(() => undefined);
          try {
            if (!pin && pin !== '') {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ ok: false, canceled: true }));
            } else {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ ok: true, pin: String(pin || '') }));
            }
          } finally {
            setBusy(false);
          }
          return;
        }
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, message: 'Not found' }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        try { setBusy(false); } catch {}
        res.end(JSON.stringify({ ok: false, message: e.message }));
      }
    });
    srv.listen(0, '127.0.0.1', () => {
      pinPrompt.server = srv;
      pinPrompt.port = srv.address().port;
      pinPrompt.token = token;
      logger(`[pin] prompt server on 127.0.0.1:${pinPrompt.port}`);
      resolve({ port: pinPrompt.port, token: pinPrompt.token });
      // Pre-warm the PIN window in the background so the first sign request
      // shows it instantly instead of waiting 3-4 s for window creation.
      setImmediate(() => { try { prewarmPinWindow(); } catch {} });
    });
  });
  return pinPrompt.ready;
}

module.exports = { ensureReady };