'use strict';
/**
 * agent/timeServerClient.js
 * Thin client for time-server health and signing authorization endpoints.
 */

const DEFAULT_BASE_URL = 'http://127.0.0.1:5001';

const DEFAULT_TIMEOUT_MS = 3000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

  return requestJson(endpoint, {
    method: 'POST',
    timeoutMs,
    retries,
    headers: {
      'x-api-key': effectiveApiKey,
    },
    body: payload,
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
  checkHealth,
  createAuthorization,
  completeAuthorization,
};
