(function (global) {
  const DSCAgent = global.DSCAgent;
  if (!DSCAgent) {
    console.warn('[DSC] dsc-agent-client.iife.js must be loaded before autowire');
    return;
  }

  function $(sel) { return document.querySelector(sel); }

  async function signOne(agent, file, opts) {
    const ab = await DSCAgent.utils.fileToArrayBuffer(file);
    return agent.signPdf(ab, opts);
  }

  async function discoverAndWire(cfg = {}) {
    const fileSel = cfg.file || '#dsc-file';
    const btnSel = cfg.button || '#dsc-sign';
    const statusSel = cfg.status || '#dsc-status';
    const downloadSel = cfg.download || '#dsc-download';
    const viewerSel = cfg.viewer || '#dsc-viewer';
    const reason = cfg.reason || undefined; // default applied later

    const fileEl = $(fileSel);
    const btnEl = $(btnSel);
    const statusEl = $(statusSel);
    const dlEl = $(downloadSel);
    const viewerEl = $(viewerSel);

    function setStatus(msg, ok = null) {
      if (!statusEl) return;
      statusEl.textContent = msg || '';
      statusEl.className = ok === true ? 'ok' : ok === false ? 'err' : '';
    }

    let agent = null;
    try {
      agent = await DSCAgent.discover();
      setStatus('Agent connected', true);
    } catch (e) {
      setStatus(e.message || 'Agent not found', false);
      if (btnEl) btnEl.disabled = true;
      return;
    }

    if (btnEl) btnEl.disabled = false;
    if (!btnEl || !fileEl) return;

    btnEl.addEventListener('click', async () => {
      try {
        setStatus('');
        const f = fileEl.files && fileEl.files[0];
        if (!f) throw new Error('Choose a PDF file first');
        if (f.type && !/pdf/i.test(f.type)) throw new Error('Selected file is not a PDF');
        btnEl.disabled = true;
        setStatus('Signing... authorize on your token if prompted.');

        const info = await agent.health().catch(() => ({}));
        const promptAvailable = !!(info && info.promptAvailable);
        const opts = {
          reason: reason || (btnEl.getAttribute('data-dsc-reason') || 'Signed via DSC Agent'),
          includeESS: ($(cfg.ess || '#dsc-ess')?.checked) ?? true,
          embedIntermediates: !!($(cfg.interm || '#dsc-interm')?.checked),
          signingTime: (cfg.signingTimeSel ? $(cfg.signingTimeSel)?.value.trim() : '') || '',
          stampAllPages: !!($(cfg.stampAll || '#dsc-stamp-all')?.checked),
        };
        if (promptAvailable) {
          opts.requirePin = true;
          if (($(cfg.remember || '#dsc-remember')?.checked) === true) opts.rememberSessionPin = true;
        } else {
          const entered = global.prompt('Enter token PIN to sign:', '');
          if (!entered) throw new Error('PIN required');
          opts.pin = entered.trim();
        }

        const { signedPdfBase64 } = await signOne(agent, f, opts);

        const name = f.name.replace(/\.pdf$/i, '.signed.pdf');
        if (dlEl) {
          dlEl.href = 'data:application/pdf;base64,' + signedPdfBase64;
          dlEl.download = name;
          dlEl.style.display = '';
        } else {
          const a = document.createElement('a');
          a.href = 'data:application/pdf;base64,' + signedPdfBase64;
          a.download = name;
          document.body.appendChild(a); a.click(); a.remove();
        }
        if (viewerEl && 'data' in viewerEl) viewerEl.data = 'data:application/pdf;base64,' + signedPdfBase64;

        setStatus('Done.', true);
      } catch (e) {
        setStatus(e.message || String(e), false);
      } finally {
        btnEl.disabled = false;
      }
    });
  }

  global.DSCAuto = { wire: discoverAndWire };

  // Auto-wire on DOM ready with defaults if elements exist
  document.addEventListener('DOMContentLoaded', () => {
    const hasDefaults = document.querySelector('#dsc-file') && document.querySelector('#dsc-sign');
    if (hasDefaults) discoverAndWire().catch(() => {});
  });
})(typeof window !== 'undefined' ? window : this);

