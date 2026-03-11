'use strict';


require('dotenv').config({
  path: require('path').resolve(__dirname, '..', '.env'),
});


/**
 * agent/timeServerClient.js
 * Centralized client for time server health + timestamp requests.
 */

const DEFAULT_BASE_URL = 'http://127.0.0.1:5001';
const DEFAULT_API_KEY = process.env.TIMESERVER_API_KEY ;
const DEFAULT_TIMEOUT_MS = Number(process.env.TIMESERVER_TIMEOUT_MS || 3000);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getAuthHeader(token) {
  if (!token || typeof token !== 'string') return {};
  return { Authorization: `Bearer ${token}` };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
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
      const data = text ? JSON.parse(text) : null;

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

/**
 * Request a timestamp from the time server.
 */
async function requestTimestamp(
  { name, machineHash, apiKey } = {},
  { endpoint = '/api/time', timeoutMs = 5000, retries = 1 } = {}
) {
  const effectiveApiKey = (typeof apiKey === 'string' && apiKey.trim())
    ? apiKey.trim()
    : null;

  if (!effectiveApiKey) {
    throw new Error('apiKey is required');
  }
  console.log('[timeServerClient] requestTimestamp payload:', {
    name,
    machineHash,
    hasApiKey: !!effectiveApiKey,
  });
  return requestJson(endpoint, {
    method: 'POST',
    timeoutMs,
    retries,
    body: {
      name,
      machineHash,
      apiKey: effectiveApiKey,
    },
  });
}

async function generateToken(
  { name, machineHash, apiKey } = {},
  { endpoint = '/api/auth/generate-token', timeoutMs = 5000, retries = 1 } = {}
) {
  const effectiveApiKey = (typeof apiKey === 'string' && apiKey.trim())
    ? apiKey.trim()
    : null;

  if (!effectiveApiKey) {
    throw new Error('apiKey is required');
  }
   
  
  console.log('[timeServerClient] requestTimestamp payload:', {
    name,
    machineHash,
    hasApiKey: !!effectiveApiKey,
  });

  return requestJson(endpoint, {
    method: 'POST',
    timeoutMs,
    retries,
    body: {
      name,
      machineHash,
      apiKey: effectiveApiKey,
    },
  });
}

async function requestSignAuthorization(
  token,
  payload = {},
  { endpoint = '/api/sign', timeoutMs = 5000, retries = 0 } = {}
) {
  return requestJson(endpoint, {
    method: 'POST',
    timeoutMs,
    retries,
    headers: {
      Authorization: String(token || '').trim(),
      'Content-Type': 'application/json',
    },
    body: payload,
  });
}

module.exports = {
  checkHealth,
  requestTimestamp,
  generateToken,
  requestSignAuthorization,
};   
