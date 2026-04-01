(function (global) {
  const DEFAULT_PORTS = [18080, 18081, 18082];

  function toBase64(input) {
    if (typeof input === 'string') return input;
    let bytes;
    if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
    else if (ArrayBuffer.isView(input)) bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    else throw new Error('Unsupported input: expected ArrayBuffer/TypedArray/base64 string');
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    if (typeof btoa !== 'function') throw new Error('btoa not available in this environment');
    return btoa(s);
  }

  async function fileToArrayBuffer(file) {
    if (!(file instanceof Blob)) throw new Error('Expected File/Blob');
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result);
      fr.onerror = reject;
      fr.readAsArrayBuffer(file);
    });
  }

  async function discover(timeoutMs = 6000, ports = DEFAULT_PORTS) {
    for (const p of ports) {
      try {
        const ctl = new AbortController();
        const t = setTimeout(() => ctl.abort(), timeoutMs);
        const r = await fetch(`http://127.0.0.1:${p}/health`, { signal: ctl.signal, credentials: 'include' });
        clearTimeout(t);
        if (r.ok) {
          await r.json().catch(() => ({}));
          return createClient(`http://127.0.0.1:${p}`);
        }
      } catch (_) {}
    }
    throw new Error('DSC Agent not found on localhost. Make sure it is running.');
  }

  function createClient(base) {
    async function health() {
      const r = await fetch(base + '/health', { credentials: 'include' });
      return r.json();
    }

    async function signPdf(data, opts = {}) {
      const {
        reason = 'Signed via DSC Agent',
        includeESS = true,
        embedIntermediates = false,
        signingTime = '',
        pin = '',
        requirePin = false,
        rememberSessionPin = false,
        stampAllPages = false,
      } = opts;

      const body = {
        pdfBase64: toBase64(data),
        reason,
        includeESS,
        embedIntermediates,
        signingTime,
        pin,
      };
      if (requirePin) body.requirePin = true;
      if (rememberSessionPin) body.rememberSessionPin = true;
      if (stampAllPages) body.stampAllPages = true;

      const r = await fetch(base + '/sign/pdf', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'include',
      });

      
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) throw new Error(j.message || ('HTTP ' + r.status));
      return j;
    }

    async function signPdfBatch(items, opts = {}) {
      const arrays = [];
      for (const it of items) {
        if (typeof Blob !== 'undefined' && it instanceof Blob) {
          arrays.push(await fileToArrayBuffer(it));
        } else {
          arrays.push(it);
        }
      }
      const b64s = arrays.map(toBase64);

      const {
        reason = 'Signed via DSC Agent',
        includeESS = true,
        embedIntermediates = false,
        signingTime = '',
        pin = '',
        requirePin = false,
        rememberSessionPin = false,
        stampAllPages = false,
        pinPrompt,
      } = opts;

      const payload = {
        pdfs: b64s,
        reason,
        includeESS,
        embedIntermediates,
        signingTime,
      };
      if (stampAllPages) payload.stampAllPages = true;
      if (requirePin) payload.requirePin = true;
      if (rememberSessionPin) payload.rememberSessionPin = true;
      if (pin) payload.pin = pin;

      try {
        const r = await fetch(base + '/sign/pdf-batch', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload), credentials: 'include'
        });
        const j = await r.json().catch(() => ({}));
        if (r.ok && j && j.ok && Array.isArray(j.results)) return j;
      } catch (_) {}

      const results = [];
      let effectivePin = pin;
      let prompted = false;
      for (let i = 0; i < arrays.length; i++) {
        const perItem = { reason, includeESS, embedIntermediates, signingTime, stampAllPages };
        if (rememberSessionPin && i === 0) perItem.rememberSessionPin = true;
        if (requirePin && i === 0) perItem.requirePin = true;
        if (!effectivePin && typeof pinPrompt === 'function' && !prompted) {
          // eslint-disable-next-line no-await-in-loop
          effectivePin = (await pinPrompt()) || '';
          prompted = true;
        }
        if (effectivePin) perItem.pin = effectivePin;
        try {
          // eslint-disable-next-line no-await-in-loop
          const j = await signPdf(arrays[i], perItem);
          results.push({ ok: true, signedPdfBase64: j.signedPdfBase64 });
        } catch (e) {
          results.push({ ok: false, message: e.message || String(e) });
        }
      }
      return { ok: true, results };
    }

    return { base, health, signPdf, signPdfBatch };
  }

  const api = { discover, createClient, utils: { toBase64, fileToArrayBuffer } };
  global.DSCAgent = api;
})(typeof window !== 'undefined' ? window : this);

