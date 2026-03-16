const { BrowserWindow, ipcMain } = require('electron');
const http = require('http');

let pinPrompt = { server: null, port: null, token: null, ready: null, busy: false, win: null };

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

async function showPinDialog(message, getMainWindow) {
  return new Promise((resolve) => {
    try {
      // Reuse existing window if present
      if (pinPrompt.win && !pinPrompt.win.isDestroyed()) {
        try {
          pinPrompt.win.webContents.send('pin:set-message', String(message || 'Enter token PIN'));
              // Ensure the existing prompt is visible, centered and focused
              try { if (pinPrompt.win.isMinimized && pinPrompt.win.isMinimized()) pinPrompt.win.restore(); } catch {}
              try { if (pinPrompt.win.center) pinPrompt.win.center(); } catch {}
              try { pinPrompt.win.setAlwaysOnTop(true, 'modal-panel'); } catch {}
              try { pinPrompt.win.show(); } catch {}
              try { pinPrompt.win.focus(); } catch {}
              try { pinPrompt.win.webContents.focus(); } catch {}
        } catch {}
        const w = pinPrompt.win;
        let settled = false;
        const settle = (val) => { if (!settled) { settled = true; resolve(val); } };
        const onSubmit = (evt, pin) => { cleanup(); settle(pin); };
        const onCancel = () => { cleanup(); settle(undefined); };
        const onClosed = () => { cleanup(); settle(undefined); };
        const cleanup = () => {
          ipcMain.removeListener('pin:submit', onSubmit);
          ipcMain.removeListener('pin:cancel', onCancel);
          try { if (w && !w.isDestroyed()) { w.removeListener('closed', onClosed); } } catch {}
          try { if (pinPrompt.win) { pinPrompt.win.hide(); } } catch {}
        };
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
        // keep on top and request foreground focus reliably
        alwaysOnTop: true,
        acceptFirstMouse: true,
        focusable: true,
        // non-modal to avoid freezing the main UI
        modal: false,
        skipTaskbar: false,
        parent: (typeof getMainWindow === 'function' ? getMainWindow() : null) || undefined,
        show: false,
        webPreferences: { nodeIntegration: true, contextIsolation: false }
      });
      pinPrompt.win = w;
      let finished = false;
      const settle = (result) => { if (!finished) { finished = true; resolve(result); } };
      const finish = (result) => { try { if (!w.isDestroyed()) w.close(); } catch {}; settle(result); };
      w.on('closed', () => { pinPrompt.win = null; settle(undefined); });
      w.once('ready-to-show', () => {
        try {
          const pref = w.webContents.getPreferredSize();
          if (pref && pref.width && pref.height) {
            w.setContentSize(Math.min(Math.max(pref.width, 420), 640), Math.min(Math.max(pref.height, 200), 480));
          }
        } catch {}
        try { if (w.center) w.center(); } catch {}
        w.setAlwaysOnTop(true, 'modal-panel');
        w.show();
        try { w.focus(); w.webContents.focus(); } catch {}
        setTimeout(() => { try { w.focus(); w.webContents.focus(); } catch {} }, 25);
        setTimeout(() => { try { w.focus(); w.webContents.focus(); } catch {} }, 120);
      });
      w.loadFile(require('path').join(__dirname, '..', 'renderer', 'pin.html'));
      const onceReady = () => {
        w.webContents.send('pin:set-message', String(message || 'Enter token PIN'));
        w.webContents.send('pin:focus');
      };
      w.webContents.once('did-finish-load', onceReady);
      const onSubmit = (evt, pin) => finish(pin);
      const onCancel = () => finish(undefined);
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
            logger('[pin] prompt already active');
            res.writeHead(429, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, message: 'PIN prompt already active' }));
            return;
          }
          logger(`[pin] request received from ${remote}`);
          pinPrompt.busy = true;
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
            pinPrompt.busy = false;
          }
          return;
        }
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, message: 'Not found' }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        try { pinPrompt.busy = false; } catch {}
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
