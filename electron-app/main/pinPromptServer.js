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
      try { if (pinPrompt.win && !pinPrompt.win.isDestroyed()) pinPrompt.win.close(); } catch {}
      pinPrompt.win = null;
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

async function showPinDialog(message, getMainWindow) {
  return new Promise((resolve) => {
    try {
      // Reuse existing window if it is alive and not in the middle of closing.
      if (pinPrompt.win && !pinPrompt.win.isDestroyed()) {
        const w = pinPrompt.win;
        try { w.webContents.send('pin:set-message', String(message || 'Enter token PIN')); } catch {}
        forceWindowFocus(w);
        // Re-apply focus after a short delay in case the OS blocked the first attempt.
        setTimeout(() => { forceWindowFocus(w); }, 120);

        let settled = false;
        const settle = (val) => { if (!settled) { settled = true; resolve(val); } };
        const cleanup = () => {
          ipcMain.removeListener('pin:submit', onSubmit);
          ipcMain.removeListener('pin:cancel', onCancel);
          try { if (w && !w.isDestroyed()) w.removeListener('closed', onClosed); } catch {}
          try { if (pinPrompt.win && !pinPrompt.win.isDestroyed()) pinPrompt.win.hide(); } catch {}
        };
        const onSubmit = (evt, pin) => { cleanup(); settle(pin); };
        const onCancel = () => { cleanup(); settle(undefined); };
        const onClosed = () => { cleanup(); settle(undefined); };
        ipcMain.once('pin:submit', onSubmit);
        ipcMain.once('pin:cancel', onCancel);
        try { w.once('closed', onClosed); } catch {}
        return;
      }

      const w = new BrowserWindow({
        width: 460,
        height: 240,
        useContentSize: true,
        resizable: false,
        alwaysOnTop: true,
        acceptFirstMouse: true,
        focusable: true,
        modal: false,
        skipTaskbar: false,
        parent: (typeof getMainWindow === 'function' ? getMainWindow() : null) || undefined,
        show: false,
        webPreferences: { nodeIntegration: true, contextIsolation: false }
      });
      pinPrompt.win = w;

      let finished = false;
      const settle = (result) => { if (!finished) { finished = true; resolve(result); } };
      const finish = (result) => {
        // Eagerly clear the reference so any concurrent request doesn't try to
        // reuse a window that is in the middle of being destroyed.
        if (pinPrompt.win === w) pinPrompt.win = null;
        try { if (!w.isDestroyed()) w.close(); } catch {}
        settle(result);
      };

      // If the window is closed by any other means (e.g. OS, task manager), resolve as canceled.
      w.on('closed', () => { if (pinPrompt.win === w) pinPrompt.win = null; settle(undefined); });

      w.once('ready-to-show', () => {
        try {
          const pref = w.webContents.getPreferredSize();
          if (pref && pref.width && pref.height) {
            w.setContentSize(Math.min(Math.max(pref.width, 420), 640), Math.min(Math.max(pref.height, 200), 480));
          }
        } catch {}
        try { if (w.center) w.center(); } catch {}
        forceWindowFocus(w);
        // Re-apply focus at intervals to overcome OS foreground-lock.
        setTimeout(() => { forceWindowFocus(w); }, 60);
        setTimeout(() => { forceWindowFocus(w); }, 250);
      });

      w.loadFile(require('path').join(__dirname, '..', 'renderer', 'pin.html'));

      w.webContents.once('did-finish-load', () => {
        w.webContents.send('pin:set-message', String(message || 'Enter token PIN'));
        w.webContents.send('pin:focus');
      });

      const onSubmit = (evt, pin) => { ipcMain.removeListener('pin:cancel', onCancel); finish(pin); };
      const onCancel = () => { ipcMain.removeListener('pin:submit', onSubmit); finish(undefined); };
      ipcMain.once('pin:submit', onSubmit);
      ipcMain.once('pin:cancel', onCancel);
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
            // Safety: if the window has been destroyed but busy is still flagged, auto-recover.
            if (!pinPrompt.win || pinPrompt.win.isDestroyed()) {
              logger('[pin] busy flag stuck (window gone), auto-recovering');
              setBusy(false);
              pinPrompt.win = null;
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
          const pin = await showPinDialog(hint, getMainWindow).catch(() => undefined);
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
    });
  });
  return pinPrompt.ready;
}

module.exports = { ensureReady };