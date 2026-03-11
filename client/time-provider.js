(function (global) {
  if (global.DSCTime && typeof global.DSCTime.fetch === 'function') {
    return;
  }
  const DEFAULT_URL = 'https://sewasetu.assam.gov.in/digitalsig/getServerTime';

  let currentUrl = DEFAULT_URL;

  const pad = (n) => String(n).padStart(2, '0');
  const formatTimestamp = (dt) => `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;

  async function fetchJson(url) {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) {
      throw new Error(`Time service error (HTTP ${res.status})`);
    }
    return res.json();
  }

  function decodeTimestampPayload(outerPayload) {
    if (!outerPayload || typeof outerPayload.data !== 'string') {
      throw new Error('Time service payload missing data field');
    }
    const rawB64 = outerPayload.data.trim();
    if (!rawB64) {
      throw new Error('Time service returned empty data field');
    }
    let decoded;
    try {
      decoded = atob(rawB64).trim();
    } catch {
      throw new Error('Time service returned non-base64 data');
    }
    const inner = JSON.parse(decoded || 'null');
    if (!inner || typeof inner !== 'object') {
      throw new Error('Time service inner payload malformed');
    }
    return inner;
  }

  function coerceTimestamp(value) {
    if (typeof value === 'number' && Number.isFinite(value)) {
      const millis = value > 1e12 ? value : value * 1000;
      const dt = new Date(millis);
      if (!Number.isNaN(dt.getTime())) return dt;
    }
    if (typeof value === 'string' && value.trim()) {
      const raw = value.trim();
      let dt = new Date(raw);
      if (!Number.isNaN(dt.getTime())) return dt;
      dt = new Date(raw.replace('T', ' '));
      if (!Number.isNaN(dt.getTime())) return dt;
      dt = new Date(raw.replace(' ', 'T'));
      if (!Number.isNaN(dt.getTime())) return dt;
    }
    return null;
  }

  async function fetchSigningTimestamp(urlOverride) {
    const url = typeof urlOverride === 'string' && urlOverride.trim()
      ? urlOverride.trim()
      : currentUrl;
    const outer = await fetchJson(url);
    const inner = decodeTimestampPayload(outer);
    const tsValue = inner.timestamp ?? inner.time ?? inner.serverTime ?? inner.server_time ?? null;
    const dt = coerceTimestamp(tsValue);
    if (!dt) {
      throw new Error('Time service timestamp could not be parsed');
    }
    return formatTimestamp(dt);
  }

  const api = {
    async fetch(urlOverride) {
      return fetchSigningTimestamp(urlOverride);
    },
    setDefaultUrl(url) {
      if (typeof url === 'string' && url.trim()) {
        currentUrl = url.trim();
      }
    },
    getDefaultUrl() {
      return currentUrl;
    },
  };

  Object.defineProperty(global, 'DSCTime', {
    value: api,
    writable: false,
    configurable: false,
  });
})(window);
