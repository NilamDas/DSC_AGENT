const { ipcRenderer } = require('electron');

const $ = (id) => document.getElementById(id);

// Ensure the PIN input gets focus immediately
window.addEventListener('DOMContentLoaded', () => {
  const el = $('pin');
  if (el) { try { el.focus(); el.select(); } catch {} }
});

ipcRenderer.on('pin:set-message', (evt, msg) => {
  const el = $('message');
  if (el) el.textContent = msg || 'Enter token PIN';
  // Also refocus input when message arrives
  const pinEl = $('pin');
  if (pinEl) { try { pinEl.focus(); pinEl.select(); } catch {} }
});

ipcRenderer.on('pin:focus', () => {
  const el = $('pin');
  if (el) { try { el.focus(); el.select(); } catch {} }
});

// Clear the input field before the window is shown for a new request.
ipcRenderer.on('pin:reset', () => {
  const el = $('pin');
  if (el) { el.value = ''; try { el.focus(); } catch {} }
});

$('btn-ok').addEventListener('click', () => {
  const v = $('pin').value || '';
  ipcRenderer.send('pin:submit', v);
});
$('btn-cancel').addEventListener('click', () => {
  ipcRenderer.send('pin:cancel');
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    $('btn-ok').click();
  } else if (e.key === 'Escape') {
    $('btn-cancel').click();
  }
});
