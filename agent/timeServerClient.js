'use strict';
/**
 * agent/timeServerClient.js
 * Thin client for time-server health and signing authorization endpoints.
 */

const http = require('http');
const https = require('https');

let DEFAULT_BASE_URL = 'https://103.158.204.86';
let DEFAULT_METHOD = 'GET';
let DEFAULT_TIME_FIELD = 'time';
let DEFAULT_ALLOW_SELF_SIGNED = false;

const DEFAULT_TIMEOUT_MS = 3000;
const httpAgent = new http.Agent({ keepAlive: true });
let httpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: true });

function resetHttpsAgent() {
  const previous = httpsAgent;
  httpsAgent = new https.Agent({
    keepAlive: true,
    rejectUnauthorized: !DEFAULT_ALLOW_SELF_SIGNED,
  });
  try { previous.destroy(); } catch {}
}

/**
 * Override the base URL / method / time-field at startup (called from dsc-agent.js after config is loaded).
 */
function configure({ baseUrl, method, timeField, allowSelfSigned } = {}) {
  if (baseUrl && typeof baseUrl === 'string' && baseUrl.trim()) {
    DEFAULT_BASE_URL = baseUrl.trim().replace(/\/$/, '');
  }
  if (method && typeof method === 'string' && method.trim()) {
    DEFAULT_METHOD = method.trim().toUpperCase();
  }
  if (timeField && typeof timeField === 'string' && timeField.trim()) {
    DEFAULT_TIME_FIELD = timeField.trim();
  }
  if (allowSelfSigned !== undefined) {
    const nextAllowSelfSigned = !!allowSelfSigned;
    if (nextAllowSelfSigned !== DEFAULT_ALLOW_SELF_SIGNED) {
      DEFAULT_ALLOW_SELF_SIGNED = nextAllowSelfSigned;
      resetHttpsAgent();
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const target = new URL(url);
  const transport = target.protocol === 'https:' ? https : http;
  const agent = target.protocol === 'https:' ? httpsAgent : httpAgent;
  return new Promise((resolve, reject) => {
    const req = transport.request(target, {
      method: options.method || 'GET',
      headers: options.headers || {},
      agent,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const status = Number(res.statusCode || 0);
        resolve({
          ok: status >= 200 && status < 300,
          status,
          statusText: res.statusMessage || '',
          text: async () => Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Time server request timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function requestJson(path, { method = 'GET', headers = {}, body, timeoutMs, retries = 1, retryDelayMs = 300 } = {}) {
  const url = `${DEFAULT_BASE_URL}${path}`;
  let lastErr;

  for (let i = 0; i <= retries; i += 1) {
    try {
      const res = await fetchWithTimeout(
        url,
        {
          method,
          headers: {
            'Content-Type': 'application/json',
            ...headers,
          },
          body: body ? JSON.stringify(body) : undefined,
        },
        timeoutMs
      );

      const text = await res.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch (parseErr) {
        const preview = text ? text.slice(0, 120).replace(/\n/g, ' ') : '';
        const e = new Error(`Time server returned non-JSON response (check timeServerUrl config). Preview: ${preview}`);
        e.status = res.status;
        throw e;
      }

      if (!res.ok) {
        const err = new Error(`HTTP ${res.status} ${res.statusText}`);
        err.status = res.status;
        err.response = data;
        throw err;
      }

      return data;
    } catch (err) {
      lastErr = err;
      if (i < retries) await sleep(retryDelayMs * (i + 1));
    }
  }

  throw lastErr;
}

async function checkHealth({ timeoutMs = 2000, retries = 1 } = {}) {
  return requestJson('/health', { method: 'GET', timeoutMs, retries });
}

async function createAuthorization(
  apiKey,
  payload = {},
  { endpoint = '/api/time', timeoutMs = 5000, retries = 0 } = {}
) {
  const effectiveApiKey = (typeof apiKey === 'string' && apiKey.trim())
    ? apiKey.trim()
    : null;

  if (!effectiveApiKey) {
    throw new Error('apiKey is required');
  }

  // Flatten payload to {name, machineHash, apiKey} as expected by the /api/time endpoint.
  // Supports both nested signer format {signer: {name, machineHash}} and flat format {name, machineHash}.
  const signerName = (payload && payload.signer && typeof payload.signer.name === 'string')
    ? payload.signer.name
    : (payload && typeof payload.name === 'string' ? payload.name : '');
  const signerMachineHash = (payload && payload.signer && typeof payload.signer.machineHash === 'string')
    ? payload.signer.machineHash
    : (payload && typeof payload.machineHash === 'string' ? payload.machineHash : '');

  const params = { name: signerName, machineHash: signerMachineHash, apiKey: effectiveApiKey, osPlatform: payload.osPlatform };
  const useMethod = DEFAULT_METHOD;

  if (useMethod === 'GET') {
    // Send params as query string for GET endpoints
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
    ).toString();
    const pathWithQuery = qs ? `${endpoint}?${qs}` : endpoint;
    return requestJson(pathWithQuery, { method: 'GET', timeoutMs, retries, headers: {} });
  }
  // POST: send as JSON body
  return requestJson(endpoint, {
    method: 'POST',
    timeoutMs,
    retries,
    headers: {},
    body: params,
  });
}


module.exports = {
  configure,
  checkHealth,
  createAuthorization,
};
