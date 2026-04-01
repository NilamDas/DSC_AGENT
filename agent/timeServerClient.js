'use strict';
/**
 * agent/timeServerClient.js
 * Thin client for time-server health and signing authorization endpoints.
 */

const https = require('https');

let DEFAULT_BASE_URL = 'https://103.158.204.86';
let DEFAULT_METHOD = 'GET';
let DEFAULT_TIME_FIELD = 'time';
let DEFAULT_ALLOW_SELF_SIGNED = false;

const DEFAULT_TIMEOUT_MS = 3000;

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
    DEFAULT_ALLOW_SELF_SIGNED = !!allowSelfSigned;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const fetchOptions = { ...options, signal: controller.signal };
  // Allow self-signed / untrusted HTTPS certs when configured.
  // Node 18+ native fetch (undici) uses 'dispatcher', not 'agent'.
  if (DEFAULT_ALLOW_SELF_SIGNED && url.startsWith('https://')) {
    try {
      const { Agent } = require('undici');
      fetchOptions.dispatcher = new Agent({ connect: { rejectUnauthorized: false } });
    } catch {
      // Fallback for node-fetch-based environments
      fetchOptions.agent = new https.Agent({ rejectUnauthorized: false });
    }
  }
  try {
    const res = await fetch(url, fetchOptions);
    return res;
  } finally {
    clearTimeout(timer);
  }
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
  { endpoint = '/api/sign/authorizations', timeoutMs = 5000, retries = 0 } = {}
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

  const params = { name: signerName, machineHash: signerMachineHash, apiKey: effectiveApiKey };
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

async function completeAuthorization(
  apiKey,
  authorizationId,
  payload = {},
  { endpoint, timeoutMs = 5000, retries = 0 } = {}
) {
  const effectiveApiKey = (typeof apiKey === 'string' && apiKey.trim())
    ? apiKey.trim()
    : null;
  const normalizedAuthorizationId = typeof authorizationId === 'string' ? authorizationId.trim() : '';

  if (!effectiveApiKey) {
    throw new Error('apiKey is required');
  }
  if (!normalizedAuthorizationId) {
    throw new Error('authorizationId is required');
  }

  const targetEndpoint = endpoint || `/api/sign/authorizations/${encodeURIComponent(normalizedAuthorizationId)}/complete`;

  return requestJson(targetEndpoint, {
    method: 'POST',
    timeoutMs,
    retries,
    headers: {
      'x-api-key': effectiveApiKey,
    },
    body: payload,
  });
}

module.exports = {
  configure,
  checkHealth,
  createAuthorization,
  completeAuthorization,
};
