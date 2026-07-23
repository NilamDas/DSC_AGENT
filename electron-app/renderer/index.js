const out = document.getElementById('out');
const statusEl = document.getElementById('status');
const $ = (id) => document.getElementById(id);

let settings = {};
const tokenState = { tokens: [], baseUrl: '', headers: {}, selected: '' };

function log(o) { out.textContent = typeof o === 'string' ? o : JSON.stringify(o, null, 2);
   if (out) {
    out.textContent = s;
  } else {
    console.log(s);
  }
 }

function setBadge(state, note = '') {
  const b = document.getElementById('status-badge');
  if (b) {
    b.classList.remove('ok', 'err', 'warn');
    if (state === 'ok') { b.classList.add('ok'); b.textContent = 'Running'; }
    else if (state === 'err') { b.classList.add('err'); b.textContent = 'Stopped'; }
    else { b.classList.add('warn'); b.textContent = 'Unknown'; }
  }
  if (statusEl) statusEl.textContent = note || '';
}

// async function refreshStatus() {
//   try {
//     const port = (settings.DSC_AGENT_PORT || '').trim() || '18080';
//     const base = `http://127.0.0.1:${port}`;
//     const r = await fetch(base + '/health');
//     if (!r.ok) throw new Error('HTTP ' + r.status);
//     const j = await r.json();
//     setBadge('ok', 'v' + (j.version || '?') + ' | Token: ' + (j.slotPresent ? 'present' : 'absent'));
//   } catch (e) {
//     setBadge('err', 'Not reachable');
//   }
// }

// Button state management
const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');

function updateButtons(isRunning, tokenPresent) {
  if (!btnStart || !btnStop) return;
  
  if (!isRunning) {
    // Agent not running: Start enabled, Stop disabled
    btnStart.disabled = false;
    btnStop.disabled = true;
  } else {
    // Agent is running
    if (tokenPresent) {
      // Token found: Start disabled, Stop enabled
      btnStart.disabled = true;
      btnStop.disabled = false;
    } else {
      // Running but no token: Start enabled (still allow retry), Stop disabled
      btnStart.disabled = false;
      btnStop.disabled = true;
    }
  }
}





let lastTokenState = null;
async function refreshStatus() {
  try {
    const port = (settings.DSC_AGENT_PORT || '').trim() || '18080';
    const base = `http://127.0.0.1:${port}`;
    const r = await fetch(base + '/health');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    const currentTokenState = j.slotPresent ? 'present' : 'absent';
    
    // Notify on token status change
    if (lastTokenState !== null && lastTokenState !== currentTokenState) {
      const msg = currentTokenState === 'present' ? 'Token found' : 'Token absent';
      if (window.DSC && typeof window.DSC.notify === 'function') {
        window.DSC.notify('DSC Agent', msg);
      }
    }
    lastTokenState = currentTokenState;

    setBadge('ok', 'v' + (j.version || '?') + ' | Token: ' + currentTokenState);
    updateButtons(true, !!j.slotPresent);
  } catch (e) {
    setBadge('err', 'Not available');
    updateButtons(false, false);
  
    // if (lastTokenState !== null) {
    //   if (window.DSC && typeof window.DSC.notify === 'function') {
    //     window.DSC.notify('DSC Agent', 'Agent not reachable');
    //   }
    //   lastTokenState = null;
    // }
  }
}

function makeCustomOption() {
  const opt = document.createElement('option');
  opt.value = '__custom__';
  opt.textContent = 'Custom';
  return opt;
}

function normalizePath(p) {
  return String(p || '').replace(/\\/g, '/').trim().toLowerCase();
}


// Retry helper for token fetches ------------------------------------------------->

async function fetchTokensWithRetry(base, headers, attempts = 15, delayMs = 300) {
  for (let i = 0; i < attempts; i++) {
    try {
      const rt = await fetch(base + '/tokens', { headers });
      if (!rt.ok) throw new Error('HTTP ' + rt.status);
      return await rt.json();
    } catch (err) {
      if (i === attempts - 1) throw err;
      const waitMs = Math.min(delayMs * (2 ** i), 2000);
      console.warn(`fetch /tokens failed (attempt ${i + 1}/${attempts}): ${err}. Retrying in ${waitMs}ms`);
      await new Promise(r => setTimeout(r, waitMs));
    }
  }
  throw new Error('fetchTokensWithRetry: unreachable');
}

// ----------------------------------------------------------------------------------

function setDllForSelection(name) {
  if (!name || name === '__custom__') return null;
  const token = tokenState.tokens.find((t) => t && t.name === name);
  if (!token) return null;
  const candidates = Array.isArray(token.candidates) ? token.candidates : [];
  if (!candidates.length) return null;
  const existing = candidates.find((c) => c && c.exists && c.path);
  const chosen = existing || candidates.find((c) => c && c.path);
  if (!chosen || !chosen.path) return null;
  const input = $('PKCS11_DLL');
  if (input) input.value = chosen.path;
  tokenState.selected = name;
  return chosen.path;
}

async function persistTokenSelection(name) {
  const next = { ...settings };
  if (name && name !== '__custom__') next.PREFERRED_TOKEN_NAME = name;
  else delete next.PREFERRED_TOKEN_NAME;
  await window.DSC.setSettings(next);
  settings = next;
}

async function syncAgentTokenSelection(name) {
  if (!tokenState.baseUrl) return;
  const headers = { ...tokenState.headers, 'Content-Type': 'application/json' };
  try {
    if (name && name !== '__custom__') {
      await fetch(`${tokenState.baseUrl}/token/select`, { method: 'POST', headers, body: JSON.stringify({ tokenName: name }) });
    } else {
      await fetch(`${tokenState.baseUrl}/token/clear`, { method: 'POST', headers });
    }
  } catch (err) {
    console.warn('Failed to sync token selection:', err);
  }
}

async function handleTokenChange() {
  const sel = $('tokenName');
  if (!sel) return;
  const value = sel.value;
  setDllForSelection(value);
  try { await persistTokenSelection(value); } catch (err) { console.warn('Failed to persist token selection:', err); }
  await syncAgentTokenSelection(value);
}

function renderTokenDropdown(response) {
  const sel = $('tokenName');
  if (!sel) return;
  sel.innerHTML = '';
  sel.appendChild(makeCustomOption());

  for (const t of tokenState.tokens) {
    const opt = document.createElement('option');
    opt.value = t.name;
    opt.textContent = t.name;
    sel.appendChild(opt);
  }

  const hasToken = (name) => !!name && tokenState.tokens.some((t) => t.name === name);
  const savedToken = (settings.PREFERRED_TOKEN_NAME || '').trim();
  const agentToken = response && response.selected && response.selected.tokenName ? response.selected.tokenName : '';
  const dllInput = $('PKCS11_DLL');
  const savedDll = ((dllInput && dllInput.value) || settings.PKCS11_DLL || '').trim();

  let chosen = '__custom__';
  if (hasToken(savedToken)) {
    chosen = savedToken;
  } else if (savedDll) {
    const match = tokenState.tokens.find((tok) => (tok.candidates || []).some((cand) => normalizePath(cand.path) === normalizePath(savedDll)));
    if (match) chosen = match.name;
  } else if (hasToken(agentToken)) {
    chosen = agentToken;
  }

  sel.value = chosen;
  if (sel.value !== chosen) sel.value = '__custom__';
  if (sel.value !== '__custom__') {
    setDllForSelection(sel.value);
    // Sync the running agent so it uses the correct named-token DLL
    syncAgentTokenSelection(sel.value).catch((err) => console.warn('Failed to sync token on load:', err));
  }
}

async function load() {
  settings = await window.DSC.getSettings();
  if ($('PKCS11_DLL')) $('PKCS11_DLL').value = settings.PKCS11_DLL || '';

  const tokenSelect = $('tokenName');
  if (tokenSelect && !tokenSelect.options.length) tokenSelect.appendChild(makeCustomOption());
  if (tokenSelect) tokenSelect.addEventListener('change', () => { handleTokenChange(); });

  updateAgentUrl();
  try { refreshStatus(); } catch {}
  try { setInterval(refreshStatus, 5000); } catch {}
  try {
    const r = await window.DSC.getDllPresets();
    if (r && r.ok && r.presets) {
      const dl = document.getElementById('dll-presets');
      dl.innerHTML = '';
      const seen = new Set();
      const saved = (settings.PKCS11_DLL || '').trim();
      if (saved) {
        const opt = document.createElement('option');
        opt.value = saved; opt.label = `${saved} (saved)`;
        dl.appendChild(opt); seen.add(saved);
      }
      for (const it of r.presets) {
        if (seen.has(it.path)) continue;
        const opt = document.createElement('option');
        opt.value = it.path;
        opt.label = it.exists ? `${it.path} (found)` : it.path;
        dl.appendChild(opt);
      }
    }
  } catch {}

  try {
    const port = (settings.DSC_AGENT_PORT || '').trim() || '18080';
    const base = `http://127.0.0.1:${port}`;
    const headers = { 'Content-Type': 'application/json' };
    if (settings.DSC_AUTH_TOKEN) headers['X-DSC-Auth'] = settings.DSC_AUTH_TOKEN;

    tokenState.baseUrl = base;
    tokenState.headers = headers;

    // const rt = await fetch(base + '/tokens', { headers });
    // if (rt.ok) {
    //   const j = await rt.json();
    //   tokenState.tokens = Array.isArray(j.tokens) ? j.tokens : [];
    //   renderTokenDropdown(j);
    // }

    // retrying fetch to handle agent startup delays
    const j = await fetchTokensWithRetry(base, headers);
    tokenState.tokens = Array.isArray(j.tokens) ? j.tokens : [];
    renderTokenDropdown(j);
    
  } catch (err) {
    console.warn('Failed to load tokens:', err);
  }

}

// document.getElementById('btn-save').addEventListener('click', async () => {
//   const current = await window.DSC.getSettings();
//   current.PKCS11_DLL = ($('PKCS11_DLL').value || '').trim();
//   await window.DSC.setSettings(current);
//   settings = current;
//   log({ ok:true, message:'DLL path saved' });
//   updateAgentUrl();
// });

document.getElementById('btn-save').addEventListener('click', async () => {
  try {
    const current = await window.DSC.getSettings();
    const dllPath = ($('PKCS11_DLL').value || '').trim();

    current.PKCS11_DLL = dllPath;
    await window.DSC.setSettings(current);
    settings = current;
    updateAgentUrl();

    // Sync the running agent immediately so it uses the saved DLL without a restart.
    // This is critical when the dropdown is on "Custom" — the agent has no other way
    // to learn about a manually-entered DLL path.
    if (dllPath && tokenState.baseUrl) {
      const headers = { ...tokenState.headers, 'Content-Type': 'application/json' };
      try {
        await fetch(`${tokenState.baseUrl}/token/select`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ dll: dllPath }),
        });
      } catch (syncErr) {
        console.warn('Failed to sync DLL with running agent:', syncErr);
      }
    }

    renderDetails('Configuration Saved', {
      ok: true,
      dll: dllPath
    }, [
      {
        label: 'Status',
        key: 'ok',
        type: 'badge',
        map: {
          true: { text: 'Saved successfully', class: 'ok' }
        }
      },
      {
        label: 'Token Driver Path',
        key: 'dll',
        type: 'code'
      }
    ]);

  } catch (e) {
    showError('Failed to save configuration', e);
  }
});




document.getElementById('btn-browse').addEventListener('click', async () => {
  const r = await window.DSC.browseDll();
  if (r && r.ok && r.file) {
    $('PKCS11_DLL').value = r.file;
  }
});

function updateAgentUrl() {
  const port = (settings.DSC_AGENT_PORT || '').trim() || '18080';
  const url = `http://127.0.0.1:${port}`;
  const el = $('AGENT_URL');
  if (el) { el.textContent = url; }
}

// async function call(pathname) {
//   try {
//     const port = (settings.DSC_AGENT_PORT || '').trim() || '18080';
//     const base = `http://127.0.0.1:${port}`;
//     const headers = { 'Content-Type': 'application/json' };
//     if (settings.DSC_AUTH_TOKEN) headers['X-DSC-Auth'] = settings.DSC_AUTH_TOKEN;
//     const r = await fetch(base + pathname, { headers });
//     const j = await r.json();
//     log(j);
//   } catch (e) {
//     log(String(e));
//   }
// }

async function call(pathname, { silent = false } = {}) {
  try {
    const port = (settings.DSC_AGENT_PORT || '').trim() || '18080';
    const base = `http://127.0.0.1:${port}`;

    const headers = { 'Content-Type': 'application/json' };
    if (settings.DSC_AUTH_TOKEN) {
      headers['X-DSC-Auth'] = settings.DSC_AUTH_TOKEN;
    }

    const res = await fetch(base + pathname, { headers });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }

    const json = await res.json();

    // keep raw logging (debug)
    if (!silent) log(json);

    return json; // 🔑 THIS is the fix
  } catch (err) {
    log(String(err));
    throw err; // let UI decide how to show it
  }
}



// Details rendering --------------------------------------------------------------
function renderDetails(title, data, schema) {
  const view = document.getElementById('details-view');
  const body = document.getElementById('details-body');
  const raw = document.getElementById('details-raw');

  document.getElementById('details-title').textContent = title;
  body.innerHTML = '';
  view.style.display = 'block';

  schema.forEach(item => {
    const row = document.createElement('div');
    row.className = 'row';

    const label = document.createElement('label');
    label.textContent = item.label;

    const value = document.createElement('div');

    const v = data[item.key];

    if (item.type === 'badge') {
      const span = document.createElement('span');
      span.className = 'badge ' + (item.map?.[v]?.class || 'warn');
      span.textContent = item.map?.[v]?.text ?? String(v);
      value.appendChild(span);
    }
    else if (item.type === 'boolean') {
      value.textContent = v ? 'Yes' : 'No';
    }
    else if (item.type === 'code') {
      const code = document.createElement('code');
      code.textContent = v ?? '—';
      value.appendChild(code);
    }
    else {
      value.textContent = v ?? '—';
    }
    row.appendChild(label);
    row.appendChild(value);
    body.appendChild(row);
  });

  // raw.textContent = JSON.stringify(data, null, 2);
}

function renderCertList(certs) {
  if (!Array.isArray(certs) || !certs.length) return;

  const body = document.getElementById('details-body');

  certs.forEach((c, i) => {
    const hr = document.createElement('hr');
    hr.style.border = '0';
    hr.style.borderTop = '1px dashed #ddd';
    hr.style.margin = '8px 0';
    body.appendChild(hr);

    addRow('Label', c.label);
    addRow('Serial', c.serial);
    addRow('Expires', c.expires);
  });
}

function addRow(labelText, valueText) {
  const row = document.createElement('div');
  row.className = 'row';

  const label = document.createElement('label');
  label.textContent = labelText;

  const value = document.createElement('div');
  value.textContent = valueText || '—';

  row.appendChild(label);
  row.appendChild(value);

  document.getElementById('details-body').appendChild(row);
}



function showError(title, err) {
  renderDetails(title, {
    message: err?.message || String(err)
  }, [
    {
      label: 'Error',
      key: 'message',
      type: 'badge',
      map: {
        undefined: { text: 'Failed', class: 'err' }
      }
    }
  ]);
}





// document.getElementById('btn-health').addEventListener('click', () => call('/health'));
// document.getElementById('btn-health').addEventListener('click', async () => {
//   try {
//     const data = await call('/health', { silent: true });

//     renderDetails('Health Status', data, [
//       {
//         label: 'Agent',
//         key: 'ok',
//         type: 'badge',
//         map: {
//           true:  { text: 'Running', class: 'ok' },
//           false: { text: 'Error',   class: 'err' }
//         }
//       },
//       { label: 'Version', key: 'version' },
//       {
//         label: 'Token',
//         key: 'slotPresent',
//         type: 'badge',
//         map: {
//           true:  { text: 'Detected', class: 'ok' },
//           false: { text: 'Not found', class: 'warn' }
//         }
//       },
//       { label: 'Token Driver Path', key: 'dll', type: 'code' },
//     ]);
//   } catch (e) {
//     showError('Health check failed', e);
//   }
// });



// document.getElementById('btn-certs').addEventListener('click', () => call('/certs'));
// document.getElementById('btn-certs').addEventListener('click', async () => {
//   try {
//     const data = await call('/certs', { silent: true });
//     renderCertList(data.certs);

//   } catch (e) {
//     showError('Certificate load failed', e);
//   }
// });


// document.getElementById('btn-health').addEventListener('click', () => refreshStatus());

load();

try { window.addEventListener('focus', () => { refreshStatus(); }); } catch {}


// PKCS#11 help toggle
const pkHelpBtn = document.getElementById('pkcs11-help');
const pkHelpPanel = document.getElementById('pkcs11-help-panel');
const pkHelpClose = document.getElementById('pkcs11-help-close');

if (pkHelpBtn && pkHelpPanel) {
  pkHelpBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    pkHelpPanel.style.display = pkHelpPanel.style.display === 'none' ? 'block' : 'none';
  });
  if (pkHelpClose) pkHelpClose.addEventListener('click', () => { pkHelpPanel.style.display = 'none'; });
  // click outside closes panel
  document.addEventListener('click', (e) => {
    if (!pkHelpPanel.contains(e.target) && e.target !== pkHelpBtn) pkHelpPanel.style.display = 'none';
  });
  // Esc closes panel
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') pkHelpPanel.style.display = 'none'; });
}



// click handlers
document.getElementById('btn-start').addEventListener('click', async () => {
  // await window.DSC.startAgent();
  // statusEl.textContent = 'Starting.';

  if (btnStart) btnStart.disabled = true;
  if (btnStop) btnStop.disabled = true;  // disable Stop while starting
  try {
    await window.DSC.startAgent();
    statusEl.textContent = 'Starting...';
    // actual state will be updated by refreshStatus polling
  } catch (err) {
    console.warn('startAgent failed', err);
    if (btnStart) btnStart.disabled = false;
    if (btnStop) btnStop.disabled = true;
  }
});


document.getElementById('btn-stop').addEventListener('click', async () => {
  // await window.DSC.stopAgent();
  // statusEl.textContent = 'Stopped';

  if (btnStop) btnStop.disabled = true;
  try {
    await window.DSC.stopAgent();
    statusEl.textContent = 'Stopped';
    updateButtons(false, false);
  } catch (err) {
    console.warn('stopAgent failed', err);
  }
});
